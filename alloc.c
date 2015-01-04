#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sysinfo.h>
#include <unistd.h>

#include "bump.h"
#include "chunk.h"
#include "extent.h"
#include "huge.h"
#include "memory.h"
#include "util.h"

#ifndef thread_local
#define thread_local _Thread_local
#endif

#define N_CLASS 32
#define MIN_ALIGN 16
#define SLAB_SIZE (64 * 1024)
#define CACHE_SIZE (16 * 1024)
#define MAX_SMALL 512
#define MAX_LARGE (CHUNK_SIZE - (sizeof(struct chunk) + sizeof(struct large)))

struct large {
    size_t size; // does not include the header
    max_align_t data[];
};

struct slot {
    struct slot *next;
    uint8_t data[];
};

struct slab {
    struct slab *next;
    size_t size;
    struct slot *next_slot;
    uint8_t data[];
};

struct chunk {
    int arena;
    bool small;
    max_align_t data[];
};

struct arena {
    pthread_mutex_t mutex;
    struct slab *free_slab;
    struct slab *partial_slab[N_CLASS];

    extent_tree large_addr;
    extent_tree large_size_addr;
};

static atomic_bool initialized = ATOMIC_VAR_INIT(false);
static pthread_mutex_t init_mutex = PTHREAD_MUTEX_INITIALIZER;

static struct arena *arenas;
static int n_arenas_init = 0;
static int n_arenas = 0;

static pthread_key_t tcache_key;

struct thread_cache {
    struct slot *bin[N_CLASS];
    size_t bin_size[N_CLASS];
    int arena_index;
    bool dead;
};

__attribute__((tls_model("initial-exec")))
static thread_local struct thread_cache tcache = {{NULL}, {}, -1, false};

static void slab_deallocate(struct arena *arena, struct slab *slab, struct slot *ptr, size_t bin);

static void tcache_destroy(void *key) {
    struct thread_cache *cache = key;
    for (int a = 0; a < n_arenas; a++) {
        struct arena *arena = &arenas[a];
        bool locked = false;
        for (size_t bin = 0; bin < N_CLASS; bin++) {
            struct slot **last_next = &cache->bin[bin];
            struct slot *slot = cache->bin[bin];

            while (slot) {
                struct slot *next = slot->next;
                struct chunk *chunk = CHUNK_ADDR2BASE(slot);
                assert(chunk->small);
                if (chunk->arena == a) {
                    if (!locked) {
                        pthread_mutex_lock(&arena->mutex);
                        locked = true;
                    }
                    struct slab *slab = ALIGNMENT_ADDR2BASE(slot, SLAB_SIZE);
                    slab_deallocate(arena, slab, slot, bin);
                    *last_next = next;
                } else {
                    last_next = &slot->next;
                }
                slot = next;
            }
        }
        if (locked) {
            pthread_mutex_unlock(&arena->mutex);
        }
    }
    cache->dead = true;
}

static void pick_arena(struct thread_cache *cache) {
    cache->arena_index = sched_getcpu();
    if (cache->arena_index == -1 || cache->arena_index > n_arenas_init) {
        cache->arena_index = 0;
    }
}

static void thread_init(struct thread_cache *cache) {
    pick_arena(cache);
    pthread_setspecific(tcache_key, cache);
}

static bool malloc_init(struct thread_cache *cache) {
    if (likely(cache->arena_index != -1)) {
        return false;
    }

    if (likely(atomic_load_explicit(&initialized, memory_order_consume))) {
        thread_init(cache);
        return false;
    }

    pthread_mutex_lock(&init_mutex);

    if (atomic_load_explicit(&initialized, memory_order_consume)) {
        pthread_mutex_unlock(&init_mutex);
        thread_init(cache);
        return false;
    }

    if (!arenas) {
        n_arenas = get_nprocs();
        arenas = bump_alloc(sizeof(struct arena) * n_arenas);
    }

    if (!arenas) {
        pthread_mutex_unlock(&init_mutex);
        return true;
    }

    if (pthread_key_create(&tcache_key, tcache_destroy)) {
        pthread_mutex_unlock(&init_mutex);
        return true;
    }

    for (; n_arenas_init < n_arenas; n_arenas_init++) {
        struct arena *arena = &arenas[n_arenas_init];
        if (pthread_mutex_init(&arena->mutex, NULL)) {
            pthread_mutex_unlock(&init_mutex);
            return true;
        }
        extent_tree_ad_new(&arena->large_addr);
        extent_tree_szad_new(&arena->large_size_addr);
    }

    huge_init();
    chunk_init();
    atomic_store_explicit(&initialized, true, memory_order_release);

    pthread_mutex_unlock(&init_mutex);
    thread_init(cache);
    return false;
}

static struct arena *get_arena(struct thread_cache *cache) {
    if (pthread_mutex_trylock(&arenas[cache->arena_index].mutex)) {
        pick_arena(cache);
        pthread_mutex_lock(&arenas[cache->arena_index].mutex);
    }
    return &arenas[cache->arena_index];
}

static void *slab_first_alloc(struct slab *slab, size_t size) {
    slab->size = size;

    struct slot *slot = (struct slot *)ALIGNMENT_CEILING((uintptr_t)slab->data, MIN_ALIGN);
    void *ret = slot;
    void *slab_end = (char *)slab + SLAB_SIZE;

    slot = (struct slot *)((char *)slot + size);
    while ((uintptr_t)slot + size < (uintptr_t)slab_end) {
        slot->next = slab->next_slot;
        slab->next_slot = slot;
        slot = (struct slot *)((char *)slot + size);
    }

    return ret;
}

static void *slab_allocate(struct arena *arena, size_t size, size_t bin) {
    if (!arena->partial_slab[bin]) {
        if (arena->free_slab) {
            struct slab *slab = arena->free_slab;
            arena->free_slab = arena->free_slab->next;

            slab->next = arena->partial_slab[bin];
            arena->partial_slab[bin] = slab;

            return slab_first_alloc(slab, size);
        }

        struct chunk *chunk = chunk_alloc(NULL, CHUNK_SIZE);
        if (!chunk) {
            return NULL;
        }
        chunk->arena = arena - arenas;
        chunk->small = true;

        struct slab *slab = (struct slab *)ALIGNMENT_CEILING((uintptr_t)chunk->data, SLAB_SIZE);
        slab->next = arena->partial_slab[bin];
        arena->partial_slab[bin] = slab;

        void *chunk_end = (char *)chunk + CHUNK_SIZE;
        while ((uintptr_t)slab + SLAB_SIZE < (uintptr_t)chunk_end) {
            slab = (struct slab *)((char *)slab + SLAB_SIZE);
            slab->next = arena->free_slab;
            arena->free_slab = slab;
        }

        slab = arena->partial_slab[bin];

        return slab_first_alloc(slab, size);
    }

    struct slab *slab = arena->partial_slab[bin];
    struct slot *slot = slab->next_slot;
    slab->next_slot = slab->next_slot->next;
    if (!slab->next_slot) {
        arena->partial_slab[bin] = arena->partial_slab[bin]->next;
    }

    return slot;
}

static size_t size2bin(size_t size) {
    return (size >> 4) - 1;
}

static void slab_deallocate(struct arena *arena, struct slab *slab, struct slot *ptr, size_t bin) {
    struct slot *slot = ptr;
    slot->next = slab->next_slot;
    slab->next_slot = slot;

    if (!slot->next) {
        slab->next = arena->partial_slab[bin];
        arena->partial_slab[bin] = slab;
    }
}

static void *allocate_small(struct thread_cache *cache, size_t size) {
    size_t bin = size2bin(size);
    struct slot *slot = cache->bin[bin];

    if (unlikely(cache->dead)) {
        struct arena *arena = get_arena(cache);
        void *ptr = slab_allocate(arena, size, bin);
        pthread_mutex_unlock(&arena->mutex);
        return ptr;
    }

    if (slot) {
        cache->bin[bin] = slot->next;
        cache->bin_size[bin] -= size;
        return slot;
    }

    struct arena *arena = get_arena(cache);

    void *ptr = slab_allocate(arena, size, bin);

    while (cache->bin_size[bin] + size < CACHE_SIZE / 2) {
        struct slot *slot = slab_allocate(arena, size, bin);
        if (!slot) {
            pthread_mutex_unlock(&arena->mutex);
            return ptr;
        }
        slot->next = cache->bin[bin];
        cache->bin[bin] = slot;
        cache->bin_size[bin] += size;
    }

    pthread_mutex_unlock(&arena->mutex);
    return ptr;
}

static struct extent_node *slab_node_alloc(struct arena *arena) {
    size_t size = sizeof(struct extent_node);
    return slab_allocate(arena, size, size2bin(size));
}

static void slab_node_free(struct arena *arena, struct extent_node *node) {
    struct slab *slab = ALIGNMENT_ADDR2BASE(node, SLAB_SIZE);
    slab_deallocate(arena, slab, (struct slot *)node, size2bin(sizeof(struct extent_node)));
}

static void large_free(struct arena *arena, void *chunk, size_t size) {
    struct extent_node key;
    key.addr = (void *)((uintptr_t)chunk + size);
    struct extent_node *node = extent_tree_ad_nsearch(&arena->large_addr, &key);
    /* Try to coalesce forward. */
    if (node && node->addr == key.addr) {
        /*
         * Coalesce chunk with the following address range.  This does
         * not change the position within chunks_ad, so only
         * remove/insert from/into chunks_szad.
         */
        extent_tree_szad_remove(&arena->large_size_addr, node);
        node->addr = chunk;
        node->size += size;
        extent_tree_szad_insert(&arena->large_size_addr, node);
    } else {
        node = slab_node_alloc(arena);
        /* Coalescing forward failed, so insert a new node. */
        if (!node) {
            /*
             * node_alloc() failed, which is an exceedingly
             * unlikely failure.  Leak allocation.
             */
            return;
        }
        node->addr = chunk;
        node->size = size;
        extent_tree_ad_insert(&arena->large_addr, node);
        extent_tree_szad_insert(&arena->large_size_addr, node);
    }

    /* Try to coalesce backward. */
    struct extent_node *prev = extent_tree_ad_prev(&arena->large_addr, node);
    if (prev && (void *)((uintptr_t)prev->addr + prev->size) == chunk) {
        /*
         * Coalesce chunk with the previous address range.  This does
         * not change the position within chunks_ad, so only
         * remove/insert node from/into chunks_szad.
         */
        extent_tree_szad_remove(&arena->large_size_addr, prev);
        extent_tree_ad_remove(&arena->large_addr, prev);

        extent_tree_szad_remove(&arena->large_size_addr, node);
        node->addr = prev->addr;
        node->size += prev->size;
        extent_tree_szad_insert(&arena->large_size_addr, node);

        slab_node_free(arena, prev);
    }
}

static void *large_recycle(struct arena *arena, void *new_addr, size_t size, size_t alignment) {
    size_t alloc_size = size + alignment - MIN_ALIGN;
    /* Beware size_t wrap-around. */
    if (alloc_size < size)
        return NULL;
    struct extent_node key;
    key.addr = new_addr;
    key.size = alloc_size;
    struct extent_node *node = extent_tree_szad_nsearch(&arena->large_size_addr, &key);
    if (!node || (new_addr && node->addr != new_addr)) {
        return NULL;
    }
    size_t leadsize = ALIGNMENT_CEILING((uintptr_t)node->addr, alignment) - (uintptr_t)node->addr;
    assert(node->size >= leadsize + size);
    size_t trailsize = node->size - leadsize - size;
    void *ret = (void *)((uintptr_t)node->addr + leadsize);
    /* Remove node from the tree. */
    extent_tree_szad_remove(&arena->large_size_addr, node);
    extent_tree_ad_remove(&arena->large_addr, node);
    if (leadsize) {
        /* Insert the leading space as a smaller chunk. */
        node->size = leadsize;
        extent_tree_szad_insert(&arena->large_size_addr, node);
        extent_tree_ad_insert(&arena->large_addr, node);
        node = NULL;
    }
    if (trailsize) {
        /* Insert the trailing space as a smaller chunk. */
        if (!node) {
            node = slab_node_alloc(arena);
            if (!node) {
                large_free(arena, ret, size);
                return NULL;
            }
        }
        node->addr = (void *)((uintptr_t)(ret) + size);
        node->size = trailsize;
        extent_tree_szad_insert(&arena->large_size_addr, node);
        extent_tree_ad_insert(&arena->large_addr, node);
        node = NULL;
    }

    if (node)
        slab_node_free(arena, node);
    return ret;
}

static void *allocate_large(struct thread_cache *cache, void *new_addr, size_t size) {
    struct arena *arena = get_arena(cache);

    void *ptr;
    if ((ptr = large_recycle(arena, new_addr, size + sizeof(struct large), MIN_ALIGN))) {
        pthread_mutex_unlock(&arena->mutex);
        struct large *head = ptr;
        head->size = size;
        return head->data;
    }
    if (new_addr) {
        pthread_mutex_unlock(&arena->mutex);
        return NULL;
    }

    struct chunk *chunk = chunk_alloc(NULL, CHUNK_SIZE);
    if (!chunk) {
        pthread_mutex_unlock(&arena->mutex);
        return NULL;
    }
    chunk->arena = cache->arena_index;
    chunk->small = false;

    struct large *head = (struct large *)((char *)chunk + sizeof(struct chunk));
    head->size = size;
    void *end = (char *)head->data + size;
    void *chunk_end = (char *)chunk + CHUNK_SIZE;
    large_free(arena, end, chunk_end - end);

    pthread_mutex_unlock(&arena->mutex);

    return head->data;
}

static bool large_realloc_no_move(void *ptr, size_t old_size, size_t new_size) {
    struct chunk *chunk = CHUNK_ADDR2BASE(ptr);
    assert(!chunk->small);
    struct arena *arena = &arenas[chunk->arena];
    struct large *head = (struct large *)((char *)ptr - sizeof(struct large));

    if (old_size < new_size) {
        void *expand_addr = (char *)ptr + old_size;
        size_t expand_size = new_size - old_size;

        pthread_mutex_lock(&arena->mutex);
        void *trail = large_recycle(arena, expand_addr, expand_size, MIN_ALIGN);
        if (!trail) {
            pthread_mutex_unlock(&arena->mutex);
            return true;
        }
        assert(trail == expand_addr);
        head->size = new_size;
        pthread_mutex_unlock(&arena->mutex);
        return false;
    }
    assert(new_size < old_size);

    void *excess_addr = (char *)ptr + new_size;
    size_t excess_size = old_size - new_size;
    head->size = new_size;

    pthread_mutex_lock(&arena->mutex);
    large_free(arena, excess_addr, excess_size);
    pthread_mutex_unlock(&arena->mutex);

    return false;
}

static void *allocate(struct thread_cache *cache, size_t size) {
    if (size <= MAX_SMALL) {
        size_t real_size = (size + 15) & ~15;
        return allocate_small(cache, real_size);
    }

    if (size <= MAX_LARGE) {
        size_t real_size = (size + 15) & ~15;
        return allocate_large(cache, NULL, real_size);
    }

    return huge_alloc(size);
}

static void deallocate_small(struct thread_cache *cache, void *ptr) {
    struct slot *slot = ptr;
    struct slab *slab = ALIGNMENT_ADDR2BASE(slot, SLAB_SIZE);
    size_t size = slab->size;
    size_t bin = size2bin(size);

    if (unlikely(cache->dead)) {
        struct chunk *chunk = CHUNK_ADDR2BASE(slot);
        struct arena *arena = &arenas[chunk->arena];
        pthread_mutex_lock(&arena->mutex);
        slab_deallocate(arena, slab, slot, bin);
        pthread_mutex_unlock(&arena->mutex);
        return;
    }

    slot->next = cache->bin[bin];
    cache->bin[bin] = slot;
    cache->bin_size[bin] += size;

    if (cache->bin_size[bin] > CACHE_SIZE) {
        cache->bin_size[bin] = size;
        while (cache->bin_size[bin] < CACHE_SIZE / 2) {
            slot = slot->next;
            assert(slot);
            cache->bin_size[bin] += size;
        }

        struct slot *flush = slot->next;
        slot->next = NULL;

        for (int a = 0; a < n_arenas; a++) {
            struct arena *arena = &arenas[a];

            struct slot **last_next = &flush;
            struct slot *slot = flush;
            bool locked = false;

            while (slot) {
                struct slot *next = slot->next;
                struct chunk *chunk = CHUNK_ADDR2BASE(slot);
                assert(chunk->small);
                if (chunk->arena == a) {
                    if (!locked) {
                        pthread_mutex_lock(&arena->mutex);
                        locked = true;
                    }
                    struct slab *slab = ALIGNMENT_ADDR2BASE(slot, SLAB_SIZE);
                    slab_deallocate(arena, slab, slot, bin);
                    *last_next = next;
                } else {
                    last_next = &slot->next;
                }
                slot = next;
            }
            if (locked) {
                pthread_mutex_unlock(&arena->mutex);
            }
        }
    }
}

static void deallocate(struct thread_cache *cache, void *ptr) {
    struct chunk *chunk = CHUNK_ADDR2BASE(ptr);
    if (ptr == chunk) {
        if (!ptr) {
            return;
        }
        huge_free(ptr);
        return;
    }
    if (chunk->small) {
        deallocate_small(cache, ptr);
    } else {
        pthread_mutex_lock(&arenas[chunk->arena].mutex);
        struct large *head = (struct large *)((char *)ptr - sizeof(struct large));
        large_free(&arenas[chunk->arena], head, head->size + sizeof(struct large));
        pthread_mutex_unlock(&arenas[chunk->arena].mutex);
    }
}

static size_t alloc_size(void *ptr) {
    struct chunk *chunk = CHUNK_ADDR2BASE(ptr);
    if (ptr == chunk) {
        if (!ptr) {
            return 0;
        }
        return huge_alloc_size(ptr);
    }
    if (chunk->small) {
        struct slab *slab = ALIGNMENT_ADDR2BASE(ptr, SLAB_SIZE);
        return slab->size;
    }
    struct large *head = (struct large *)((char *)ptr - sizeof(struct large));
    return head->size;
}

EXPORT void *malloc(size_t size) {
    struct thread_cache *cache = &tcache;

    if (unlikely(malloc_init(cache))) {
        return NULL;
    }

    void *ptr = allocate(cache, size);
    if (!ptr) {
        errno = ENOMEM;
        return NULL;
    }
    return ptr;
}

EXPORT void *calloc(size_t nmemb, size_t size) {
    struct thread_cache *cache = &tcache;

    if (unlikely(malloc_init(cache))) {
        return NULL;
    }

    size_t total;
    if (size_mul_overflow(nmemb, size, &total)) {
        errno = ENOMEM;
        return NULL;
    }
    void *new_ptr = allocate(cache, total);
    if (!new_ptr) {
        errno = ENOMEM;
        return NULL;
    }
    memset(new_ptr, 0, total);
    return new_ptr;
}

EXPORT void *realloc(void *ptr, size_t size) {
    if (!ptr) {
        return malloc(size);
    }

    struct thread_cache *cache = &tcache;

    if (!size) {
        deallocate(cache, ptr);
        return NULL;
    }

    if (unlikely(malloc_init(cache))) {
        return NULL;
    }

    size_t old_size = alloc_size(ptr);

    if (old_size > MAX_LARGE && size > MAX_LARGE) {
        return huge_realloc(ptr, old_size, CHUNK_CEILING(size));
    }

    size_t real_size = (size + 15) & ~15;
    if (old_size == real_size) {
        return ptr;
    }

    if (old_size <= MAX_LARGE && real_size <= MAX_LARGE &&
        old_size > MAX_SMALL && real_size > MAX_SMALL) {
        if (!large_realloc_no_move(ptr, old_size, real_size)) {
            return ptr;
        }
    }

    void *new_ptr = allocate(cache, size);
    if (!new_ptr) {
        errno = ENOMEM;
        return NULL;
    }
    size_t copy_size = size < old_size ? size : old_size;
    memcpy(new_ptr, ptr, copy_size);
    deallocate(cache, ptr);
    return new_ptr;
}

EXPORT void free(void *ptr) {
    struct thread_cache *cache = &tcache;
    deallocate(cache, ptr);
}

EXPORT int posix_memalign(UNUSED void **memptr, UNUSED size_t alignment, UNUSED size_t size) {
    abort();
}

EXPORT void *aligned_alloc(UNUSED size_t alignment, UNUSED size_t size) {
    abort();
}

EXPORT void *valloc(UNUSED size_t size) {
    abort();
}

EXPORT void *memalign(UNUSED size_t alignment, UNUSED size_t size) {
    abort();
}

EXPORT void *pvalloc(UNUSED size_t size) {
    abort();
}

EXPORT size_t malloc_usable_size(void *ptr) {
    return alloc_size(ptr);
}

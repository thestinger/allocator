#include <string.h>

#include "chunk.h"
#include "extent.h"
#include "huge.h"
#include "memory.h"
#include "mutex.h"
#include "purge.h"
#include "util.h"

static extent_tree huge_global;
static mutex huge_global_mutex = MUTEX_INITIALIZER;
static struct extent_node *huge_nodes;

COLD void huge_init(void) {
    extent_tree_ad_new(&huge_global);
}

static struct chunk_recycler *get_recycler(struct arena *arena) {
    return arena ? &arena->chunks : NULL;
}

static struct extent_node **get_huge_nodes(struct arena *arena) {
    return arena ? &arena->huge_nodes : &huge_nodes;
}

static void maybe_lock_arena(struct arena *arena) {
    if (arena) {
        mutex_lock(&arena->mutex);
    }
}

static void maybe_unlock_arena(struct arena *arena) {
    if (arena) {
        mutex_unlock(&arena->mutex);
    }
}

static extent_tree *acquire_huge(struct arena *arena) {
    if (!arena) {
        mutex_lock(&huge_global_mutex);
        return &huge_global;
    }
    return &arena->huge;
}

static void release_huge(struct arena *arena) {
    if (!arena) {
        mutex_unlock(&huge_global_mutex);
    }
}

static void *huge_chunk_alloc(struct thread_cache *cache, size_t size, size_t alignment,
                              struct arena **out_arena) {
    struct arena *arena = get_arena(cache);
    void *chunk = chunk_recycle(&arena->chunks, NULL, size, alignment);
    if (chunk) {
        if (unlikely(memory_commit(chunk, size))) {
            chunk_free(&arena->chunks, chunk, size);
            return NULL;
        }
    } else {
        if (!(chunk = chunk_alloc(NULL, size, alignment))) {
            return NULL;
        }

        // Work around the possibility of holes created by huge_move_expand (see below).
        struct arena *chunk_arena = get_huge_arena(chunk);
        if (chunk_arena != arena) {
            mutex_unlock(&arena->mutex);
            if (chunk_arena) {
                mutex_lock(&chunk_arena->mutex);
            }
            arena = chunk_arena;
        }
    }

    *out_arena = arena;
    return chunk;
}

void *huge_alloc(struct thread_cache *cache, size_t size, size_t alignment) {
    size_t real_size = CHUNK_CEILING(size);
    struct arena *arena;
    void *chunk = huge_chunk_alloc(cache, real_size, alignment, &arena);
    if (unlikely(!chunk)) {
        return NULL;
    }

    extent_tree *huge = acquire_huge(arena);

    struct extent_node *node = node_alloc(get_huge_nodes(arena));
    if (unlikely(!node)) {
        chunk_free(get_recycler(arena), chunk, real_size);
        chunk = NULL;
    } else {
        node->size = real_size;
        node->addr = chunk;
        extent_tree_ad_insert(huge, node);
    }

    release_huge(arena);
    maybe_unlock_arena(arena);
    return chunk;
}

static void huge_update_size(struct arena *arena, void *ptr, size_t new_size) {
    struct extent_node key;
    key.addr = ptr;

    extent_tree *huge = acquire_huge(arena);
    struct extent_node *node = extent_tree_ad_search(huge, &key);
    assert(node);
    node->size = new_size;
    release_huge(arena);
}

static void huge_no_move_shrink(void *ptr, size_t old_size, size_t new_size) {
    void *excess_addr = (char *)ptr + new_size;
    size_t excess_size = old_size - new_size;

    if (purge_ratio >= 0) {
        memory_decommit(excess_addr, excess_size);
    }

    struct arena *arena = get_huge_arena(ptr);
    maybe_lock_arena(arena);
    chunk_free(get_recycler(arena), excess_addr, excess_size);
    huge_update_size(arena, ptr, new_size);
    maybe_unlock_arena(arena);
}

static bool huge_no_move_expand(void *ptr, size_t old_size, size_t new_size) {
    bool failure = true;
    void *expand_addr = (char *)ptr + old_size;
    size_t expand_size = new_size - old_size;

    struct arena *arena = get_huge_arena(ptr);
    struct chunk_recycler *chunks = get_recycler(arena);
    maybe_lock_arena(arena);
    if (chunk_recycle(chunks, expand_addr, expand_size, CHUNK_SIZE)) {
        if (unlikely(memory_commit(expand_addr, expand_size))) {
            chunk_free(chunks, expand_addr, expand_size);
        } else {
            huge_update_size(arena, ptr, new_size);
            failure = false;
        }
    }
    maybe_unlock_arena(arena);
    return failure;
}

static void *huge_move_expand(struct thread_cache *cache, void *old_addr, size_t old_size, size_t new_size) {
    struct arena *arena;
    void *new_addr = huge_chunk_alloc(cache, new_size, CHUNK_SIZE, &arena);
    if (unlikely(!new_addr)) {
        return NULL;
    }

    bool gap = true;
    if (unlikely(memory_remap_fixed(old_addr, old_size, new_addr, new_size))) {
        memcpy(new_addr, old_addr, old_size);
        if (purge_ratio >= 0) {
            memory_decommit(old_addr, old_size);
        }
        gap = false;
    } else {
        // Attempt to fill the virtual memory hole. The kernel should provide a flag for preserving
        // the old mapping to avoid the possibility of this failing and creating fragmentation.
        //
        // https://lkml.org/lkml/2014/10/2/624
        void *extra = memory_map(old_addr, old_size, false);
        if (likely(extra)) {
            if (unlikely(extra != old_addr)) {
                memory_unmap(extra, old_size);
            } else {
                gap = false;
            }
        }
    }

    struct extent_node key;
    key.addr = old_addr;

    struct arena *old_arena = get_huge_arena(old_addr);

    extent_tree *huge = acquire_huge(old_arena);
    struct extent_node *node = extent_tree_ad_search(huge, &key);
    assert(node);
    extent_tree_ad_remove(huge, node);
    node->addr = new_addr;
    node->size = new_size;

    if (arena != old_arena) {
        release_huge(old_arena);
        huge = acquire_huge(arena);
    }

    extent_tree_ad_insert(huge, node);
    release_huge(arena);

    if (!gap) {
        if (arena != old_arena && old_arena) {
            mutex_lock(&old_arena->mutex);
        }
        chunk_free(get_recycler(old_arena), old_addr, old_size);
        if (arena != old_arena && old_arena) {
            mutex_unlock(&old_arena->mutex);
        }
    }

    maybe_unlock_arena(arena);
    return new_addr;
}

void *huge_realloc(struct thread_cache *cache, void *ptr, size_t old_size, size_t new_real_size) {
    if (new_real_size > old_size) {
        if (!huge_no_move_expand(ptr, old_size, new_real_size)) {
            return ptr;
        }
        return huge_move_expand(cache, ptr, old_size, new_real_size);
    } else if (new_real_size < old_size) {
        huge_no_move_shrink(ptr, old_size, new_real_size);
    }
    return ptr;
}

void huge_free(void *ptr) {
    struct extent_node *node, key;
    key.addr = ptr;
    struct arena *arena = get_huge_arena(ptr);

    maybe_lock_arena(arena);
    extent_tree *huge = acquire_huge(arena);

    node = extent_tree_ad_search(huge, &key);
    assert(node);
    size_t size = node->size;
    extent_tree_ad_remove(huge, node);
    node_free(get_huge_nodes(arena), node);
    release_huge(arena);

    if (purge_ratio >= 0) {
        memory_decommit(ptr, size);
    }
    chunk_free(get_recycler(arena), ptr, size);
    maybe_unlock_arena(arena);
}

size_t huge_alloc_size(void *ptr) {
    struct extent_node key;
    key.addr = ptr;
    struct arena *arena = get_huge_arena(ptr);

    maybe_lock_arena(arena);
    extent_tree *huge = acquire_huge(arena);

    struct extent_node *node = extent_tree_ad_search(huge, &key);
    assert(node);
    size_t size = node->size;

    release_huge(arena);
    maybe_unlock_arena(arena);

    return size;
}

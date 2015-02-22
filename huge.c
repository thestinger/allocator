#include <string.h>

#include "chunk.h"
#include "extent.h"
#include "huge.h"
#include "memory.h"
#include "mutex.h"
#include "util.h"

static extent_tree huge;
static mutex huge_mutex = MUTEX_INITIALIZER;
static struct extent_node *huge_nodes;

COLD void huge_init(void) {
    extent_tree_ad_new(&huge);
}

static struct chunk_recycler *get_recycler(struct arena *arena) {
    return arena ? &arena->chunks : NULL;
}

static void maybe_unlock_arena(struct arena *arena) {
    if (arena) {
        mutex_unlock(&arena->mutex);
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

    mutex_lock(&huge_mutex);

    struct extent_node *node = node_alloc(&huge_nodes);
    if (!node) {
        chunk_free(get_recycler(arena), chunk, real_size);
        mutex_unlock(&huge_mutex);
        maybe_unlock_arena(arena);
        return NULL;
    }
    node->size = real_size;
    node->addr = chunk;
    extent_tree_ad_insert(&huge, node);

    mutex_unlock(&huge_mutex);
    maybe_unlock_arena(arena);

    return node->addr;
}

static void huge_update_size(void *ptr, size_t new_size) {
    struct extent_node key;
    key.addr = ptr;

    mutex_lock(&huge_mutex);
    struct extent_node *node = extent_tree_ad_search(&huge, &key);
    assert(node);
    node->size = new_size;
    mutex_unlock(&huge_mutex);
}

static void huge_no_move_shrink(void *ptr, size_t old_size, size_t new_size) {
    void *excess_addr = (char *)ptr + new_size;
    size_t excess_size = old_size - new_size;

    memory_decommit(excess_addr, excess_size);

    struct arena *arena = get_huge_arena(ptr);
    struct chunk_recycler *chunks = get_recycler(arena);
    mutex_lock(&arena->mutex);
    chunk_free(chunks, excess_addr, excess_size);
    mutex_unlock(&arena->mutex);

    huge_update_size(ptr, new_size);
}

static bool huge_no_move_expand(void *ptr, size_t old_size, size_t new_size) {
    void *expand_addr = (char *)ptr + old_size;
    size_t expand_size = new_size - old_size;

    struct arena *arena = get_huge_arena(ptr);
    struct chunk_recycler *chunks = get_recycler(arena);
    mutex_lock(&arena->mutex);
    if (chunk_recycle(chunks, expand_addr, expand_size, CHUNK_SIZE)) {
        if (unlikely(memory_commit(expand_addr, expand_size))) {
            chunk_free(chunks, expand_addr, expand_size);
            mutex_unlock(&arena->mutex);
            return NULL;
        }
        huge_update_size(ptr, new_size);
        mutex_unlock(&arena->mutex);
        return false;
    }
    mutex_unlock(&arena->mutex);
    return true;
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
        memory_decommit(old_addr, old_size);
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

    mutex_lock(&huge_mutex);
    struct extent_node *node = extent_tree_ad_search(&huge, &key);
    assert(node);
    extent_tree_ad_remove(&huge, node);
    node->addr = new_addr;
    node->size = new_size;
    extent_tree_ad_insert(&huge, node);
    mutex_unlock(&huge_mutex);

    if (!gap) {
        struct arena *old_arena = get_huge_arena(old_addr);

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

    mutex_lock(&huge_mutex);
    node = extent_tree_ad_search(&huge, &key);
    assert(node);
    size_t size = node->size;
    extent_tree_ad_remove(&huge, node);
    node_free(&huge_nodes, node);
    mutex_unlock(&huge_mutex);

    memory_decommit(ptr, size);

    struct arena *arena = get_huge_arena(ptr);
    if (arena) {
        mutex_lock(&arena->mutex);
        chunk_free(&arena->chunks, ptr, size);
        mutex_unlock(&arena->mutex);
    } else {
        chunk_free(NULL, ptr, size);
    }
}

size_t huge_alloc_size(void *ptr) {
    struct extent_node key;
    key.addr = ptr;

    mutex_lock(&huge_mutex);
    struct extent_node *node = extent_tree_ad_search(&huge, &key);
    assert(node);
    size_t size = node->size;
    mutex_unlock(&huge_mutex);

    return size;
}

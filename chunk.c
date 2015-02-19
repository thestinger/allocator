#include "chunk.h"
#include "extent.h"
#include "memory.h"
#include "mutex.h"
#include "util.h"

static extent_tree chunks_addr;
static extent_tree chunks_size_addr;
static struct extent_node *chunk_nodes;
static mutex chunks_mutex = MUTEX_INITIALIZER;

COLD void chunk_init(void) {
    extent_tree_ad_new(&chunks_addr);
    extent_tree_szad_new(&chunks_size_addr);
}

void chunk_free(void *chunk, size_t size) {
    mutex_lock(&chunks_mutex);
    struct extent_node key;
    key.addr = (void *)((uintptr_t)chunk + size);
    struct extent_node *node = extent_tree_ad_nsearch(&chunks_addr, &key);
    /* Try to coalesce forward. */
    if (node && node->addr == key.addr) {
        /*
         * Coalesce chunk with the following address range.  This does
         * not change the position within chunks_ad, so only
         * remove/insert from/into chunks_szad.
         */
        extent_tree_szad_remove(&chunks_size_addr, node);
        node->addr = chunk;
        node->size += size;
        extent_tree_szad_insert(&chunks_size_addr, node);
    } else {
        node = node_alloc(&chunk_nodes);
        /* Coalescing forward failed, so insert a new node. */
        if (!node) {
            // Failed to allocate an extent node, so just unmap the chunk(s).
            memory_unmap(chunk, size);
            goto label_return;
        }
        node->addr = chunk;
        node->size = size;
        extent_tree_ad_insert(&chunks_addr, node);
        extent_tree_szad_insert(&chunks_size_addr, node);
    }

    /* Try to coalesce backward. */
    struct extent_node *prev = extent_tree_ad_prev(&chunks_addr, node);
    if (prev && (void *)((uintptr_t)prev->addr + prev->size) == chunk) {
        /*
         * Coalesce chunk with the previous address range.  This does
         * not change the position within chunks_ad, so only
         * remove/insert node from/into chunks_szad.
         */
        extent_tree_szad_remove(&chunks_size_addr, prev);
        extent_tree_ad_remove(&chunks_addr, prev);

        extent_tree_szad_remove(&chunks_size_addr, node);
        node->addr = prev->addr;
        node->size += prev->size;
        extent_tree_szad_insert(&chunks_size_addr, node);

        node_free(&chunk_nodes, prev);
    }

label_return:
    mutex_unlock(&chunks_mutex);
}

static void *chunk_recycle(void *new_addr, size_t size, size_t alignment) {
    size_t alloc_size = size + alignment - CHUNK_SIZE;

    assert(!new_addr || alignment == CHUNK_SIZE);

    /* Beware size_t wrap-around. */
    if (alloc_size < size)
        return NULL;
    struct extent_node key;
    key.addr = new_addr;
    key.size = alloc_size;
    mutex_lock(&chunks_mutex);
    struct extent_node *node = new_addr ? extent_tree_ad_search(&chunks_addr, &key) :
        extent_tree_szad_nsearch(&chunks_size_addr, &key);
    if (!node || (new_addr && node->size < size)) {
        mutex_unlock(&chunks_mutex);
        return NULL;
    }
    size_t leadsize = ALIGNMENT_CEILING((uintptr_t)node->addr, alignment) - (uintptr_t)node->addr;
    assert(node->size >= leadsize + size);
    assert(!new_addr || leadsize == 0);
    size_t trailsize = node->size - leadsize - size;
    void *ret = (void *)((uintptr_t)node->addr + leadsize);
    if (memory_commit(ret, size)) {
        mutex_unlock(&chunks_mutex);
        return NULL;
    }

    /* Remove node from the tree. */
    extent_tree_szad_remove(&chunks_size_addr, node);
    extent_tree_ad_remove(&chunks_addr, node);
    if (leadsize) {
        /* Insert the leading space as a smaller chunk. */
        node->size = leadsize;
        extent_tree_szad_insert(&chunks_size_addr, node);
        extent_tree_ad_insert(&chunks_addr, node);
        node = NULL;
    }
    if (trailsize) {
        /* Insert the trailing space as a smaller chunk. */
        if (!node) {
            node = node_alloc(&chunk_nodes);
            if (!node) {
                mutex_unlock(&chunks_mutex);
                memory_decommit(ret, size);
                chunk_free(ret, size);
                return NULL;
            }
        }
        node->addr = (void *)((uintptr_t)(ret) + size);
        node->size = trailsize;
        extent_tree_szad_insert(&chunks_size_addr, node);
        extent_tree_ad_insert(&chunks_addr, node);
        node = NULL;
    }

    if (node) {
        node_free(&chunk_nodes, node);
    }

    mutex_unlock(&chunks_mutex);
    return ret;
}

void *chunk_alloc(void *new_addr, size_t size, size_t alignment) {
    void *ptr;
    if ((ptr = chunk_recycle(new_addr, size, alignment))) {
        return ptr;
    }
    if (new_addr) {
        return NULL;
    }
    if (!(ptr = memory_map(NULL, size, true))) {
        return NULL;
    }
    if (ALIGNMENT_ADDR2OFFSET(ptr, alignment)) {
        memory_unmap(ptr, size);
        return memory_map_aligned(NULL, size, alignment, true);
    }
    return ptr;
}

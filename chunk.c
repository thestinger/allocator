#include <assert.h>
#include <pthread.h>

#include "chunk.h"
#include "extent.h"
#include "memory.h"

static extent_tree chunks_addr;
static extent_tree chunks_size_addr;
static pthread_mutex_t chunks_mutex = PTHREAD_MUTEX_INITIALIZER;

void chunk_init(void) {
    extent_tree_ad_new(&chunks_addr);
    extent_tree_szad_new(&chunks_size_addr);
}

void chunk_free(void *chunk, size_t size) {
    memory_purge(chunk, size);

    pthread_mutex_lock(&chunks_mutex);
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
        node = node_alloc();
        /* Coalescing forward failed, so insert a new node. */
        if (!node) {
            /*
             * node_alloc() failed, which is an exceedingly
             * unlikely failure.  Leak chunk; its pages have
             * already been purged, so this is only a virtual
             * memory leak.
             */
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

        node_free(prev);
    }

label_return:
    pthread_mutex_unlock(&chunks_mutex);
}

static void *chunk_recycle(void *new_addr, size_t size, size_t alignment) {
    size_t alloc_size = size + alignment - CHUNK_SIZE;
    /* Beware size_t wrap-around. */
    if (alloc_size < size)
        return NULL;
    struct extent_node key;
    key.addr = new_addr;
    key.size = alloc_size;
    pthread_mutex_lock(&chunks_mutex);
    struct extent_node *node = extent_tree_szad_nsearch(&chunks_size_addr, &key);
    if (!node || (new_addr && node->addr != new_addr)) {
        pthread_mutex_unlock(&chunks_mutex);
        return NULL;
    }
    size_t leadsize = ALIGNMENT_CEILING((uintptr_t)node->addr, alignment) - (uintptr_t)node->addr;
    assert(node->size >= leadsize + size);
    size_t trailsize = node->size - leadsize - size;
    void *ret = (void *)((uintptr_t)node->addr + leadsize);
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
            node = node_alloc();
            if (!node) {
                pthread_mutex_unlock(&chunks_mutex);
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
    pthread_mutex_unlock(&chunks_mutex);

    if (node)
        node_free(node);
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
    if (!(ptr = memory_map(NULL, size))) {
        return NULL;
    }
    if (ALIGNMENT_ADDR2OFFSET(ptr, alignment)) {
        memory_unmap(ptr, size);
        return memory_map_aligned(NULL, size, alignment);
    }
    return ptr;
}

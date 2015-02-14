#include "bump.h"
#include "chunk.h"
#include "memory.h"
#include "mutex.h"
#include "util.h"

static mutex bump_mutex = MUTEX_INITIALIZER;
static void *bump;
static void *bump_end;

void *bump_alloc(size_t size, size_t align) {
    assert(align <= PAGE_SIZE);

    mutex_lock(&bump_mutex);

    uintptr_t ret = ALIGNMENT_CEILING((uintptr_t)bump, align);
    if (ret + size > (uintptr_t)bump_end) {
        size_t chunk_size = CHUNK_CEILING(size);
        void *ptr = memory_map(NULL, chunk_size, true);
        if (!ptr) {
            mutex_unlock(&bump_mutex);
            return NULL;
        }
        bump = ptr;
        bump_end = ptr + chunk_size;
        ret = (uintptr_t)ptr;
    }

    bump = (void *)(ret + size);
    mutex_unlock(&bump_mutex);
    return (void *)ret;
}

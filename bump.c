#include "bump.h"
#include "chunk.h"
#include "memory.h"
#include "mutex.h"

static mutex bump_mutex = MUTEX_INITIALIZER;
static void *bump;
static void *bump_end;

void *bump_alloc(size_t size) {
    mutex_lock(&bump_mutex);
    if ((uintptr_t)bump + size > (uintptr_t)bump_end) {
        size_t chunk_size = CHUNK_CEILING(size);
        void *ptr = memory_map(NULL, chunk_size);
        if (!ptr) {
            mutex_unlock(&bump_mutex);
            return NULL;
        }
        bump = ptr;
        bump_end = ptr + chunk_size;
    }

    void *ret = bump;
    bump = (void *)((char *)bump + size);
    mutex_unlock(&bump_mutex);
    return ret;
}

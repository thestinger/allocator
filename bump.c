#include <pthread.h>

#include "bump.h"
#include "chunk.h"
#include "memory.h"

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static void *bump;
static void *bump_end;

void *bump_alloc(size_t size) {
    pthread_mutex_lock(&mutex);
    if ((uintptr_t)bump + size > (uintptr_t)bump_end) {
        size_t chunk_size = CHUNK_CEILING(size);
        void *ptr = memory_map(NULL, chunk_size);
        if (!ptr) {
            pthread_mutex_unlock(&mutex);
            return NULL;
        }
        bump = ptr;
        bump_end = ptr + chunk_size;
    }

    void *ret = bump;
    bump = (void *)((char *)bump + size);
    pthread_mutex_unlock(&mutex);
    return ret;
}

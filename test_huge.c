#include <stdlib.h>

#include "chunk.h"

int main(void) {
    // mmap(NULL, CHUNK_SIZE * 4, ...)
    void *p = malloc(CHUNK_SIZE * 4);
    if (!p) return 1;

    {
        // no change to the allocation
        void *q = realloc(p, CHUNK_SIZE * 4 - (CHUNK_SIZE / 2));
        if (q != p) return 1;

        // in-place shrink, madvise purge
        q = realloc(p, CHUNK_SIZE * 2);
        if (q != p) return 1;

        // in-place shrink, madvise purge
        q = realloc(p, CHUNK_SIZE);
        if (q != p) return 1;

        // in-place expand, no syscall
        q = realloc(p, CHUNK_SIZE * 2);
        if (q != p) return 1;

        // in-place expand, no syscall
        q = realloc(p, CHUNK_SIZE * 4);
        if (q != p) return 1;
    }

    // extended/moved by mremap(..., CHUNK_SIZE * 8, MREMAP_MAYMOVE)
    //
    // if it is moved, the source is mapped back in (MREMAP_RETAIN landing would be nicer)
    p = realloc(p, CHUNK_SIZE * 8);
    if (!p) return 1;

    // mmap(NULL, CHUNK_SIZE * 16, ...)
    void *dest = malloc(CHUNK_SIZE * 16);
    if (!dest) return 1;

    // madvise purge
    free(dest);

    // moved via MREMAP_MAYMOVE|MREMAP_FIXED to dest
    //
    // the source is mapped back in (MREMAP_RETAIN landing would be nicer)
    p = realloc(p, CHUNK_SIZE * 16);
    if (p != dest) return 1;

    // madvise purge
    free(p);
    return 0;
}

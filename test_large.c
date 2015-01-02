#include <stdlib.h>

#include "chunk.h"

int main(void) {
    void *p = malloc(4096 * 4);
    if (!p) return 1;

    {
        // in-place shrink
        void *q = realloc(p, 4096 * 2);
        if (q != p) return 1;

        // in-place shrink
        q = realloc(p, 4096);
        if (q != p) return 1;

        // in-place expand
        q = realloc(p, 4096 * 2);
        if (q != p) return 1;

        // in-place expand
        q = realloc(p, 4096 * 4);
        if (q != p) return 1;

        // in-place expand
        q = realloc(p, 4096 * 8);
        if (q != p) return 1;

        // in-place expand
        q = realloc(p, 4096 * 64);
        if (q != p) return 1;
    }

    free(p);
    return 0;
}

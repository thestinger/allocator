#include <pthread.h>
#include <stdlib.h>

#define N 10000000

void *do_work(void *ptr) {
    void **p = malloc(N * sizeof(void *));

    for (size_t i = 0; i < N; i++) {
        p[i] = malloc(16);
        if (!p[i]) {
            exit(1);
        }
    }

    for (size_t i = 0; i < N; i++) {
        free(p[i]);
    }
    return ptr;
}

int main(void) {
    pthread_t thread;
    pthread_create(&thread, NULL, do_work, NULL);
    pthread_join(thread, NULL);
    return 0;
}

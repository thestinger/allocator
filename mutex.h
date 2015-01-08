#ifndef MUTEX_H
#define MUTEX_H

#include <pthread.h>
#include <stdbool.h>

#define MUTEX_INITIALIZER PTHREAD_MUTEX_INITIALIZER;
typedef pthread_mutex_t mutex;
bool mutex_init(mutex *m);
bool mutex_trylock(mutex *m);
void mutex_lock(mutex *m);
void mutex_unlock(mutex *m);

#endif

#ifndef MUTEX_H
#define MUTEX_H

#include <stdbool.h>

#ifdef __linux__

#include <stdatomic.h>

#define MUTEX_INITIALIZER 0
typedef atomic_int mutex;

#else

#include <pthread.h>

#define MUTEX_INITIALIZER PTHREAD_MUTEX_INITIALIZER;
typedef pthread_mutex_t mutex;

#endif

bool mutex_init(mutex *m);
bool mutex_trylock(mutex *m);
void mutex_lock(mutex *m);
void mutex_unlock(mutex *m);

#endif

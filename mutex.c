#include <assert.h>
#include <errno.h>

#include "mutex.h"
#include "util.h"

bool mutex_init(mutex *m) {
    return pthread_mutex_init(m, NULL);
}

bool mutex_trylock(mutex *m) {
    int ret = pthread_mutex_trylock(m);
    assert(!ret || ret == EBUSY);
    return ret;
}

void mutex_lock(mutex *m) {
    UNUSED int ret = pthread_mutex_lock(m);
    assert(!ret);
}

void mutex_unlock(mutex *m) {
    UNUSED int ret = pthread_mutex_unlock(m);
    assert(!ret);
}

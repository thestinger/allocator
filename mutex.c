#include <assert.h>
#include <errno.h>

#include "mutex.h"
#include "util.h"

#ifdef __linux__

#include <linux/futex.h>
#include <syscall.h>
#include <time.h>
#include <unistd.h>

static int sys_futex(void *uaddr, int op, int val1, struct timespec *timeout, void *uaddr2,
                     int val3) {
    return syscall(SYS_futex, uaddr, op, val1, timeout, uaddr2, val3);
}

bool mutex_init(mutex *m) {
    *m = 0;
    return false;
}

bool mutex_trylock(mutex *m) {
    int expected = 0;
    return !atomic_compare_exchange_strong_explicit(m, &expected, 1, memory_order_acquire,
                                                    memory_order_relaxed);
}

void mutex_lock(mutex *m) {
    int expected = 0;
    if (!atomic_compare_exchange_strong_explicit(m, &expected, 1, memory_order_acquire,
                                                 memory_order_relaxed)) {
        if (expected != 2) {
            expected = atomic_exchange_explicit(m, 2, memory_order_acquire);
        }
        while (expected) {
            sys_futex(m, FUTEX_WAIT_PRIVATE, 2, NULL, NULL, 0);
            expected = atomic_exchange_explicit(m, 2, memory_order_acquire);
        }
    }
}

void mutex_unlock(mutex *m) {
    if (atomic_fetch_sub_explicit(m, 1, memory_order_release) != 1) {
        atomic_store_explicit(m, 0, memory_order_release);
        sys_futex(m, FUTEX_WAKE_PRIVATE, 1, NULL, NULL, 0);
    }
}

#else

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

#endif

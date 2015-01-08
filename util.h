#ifndef UTIL_H
#define UTIL_H

#include <stddef.h>
#include <stdint.h>

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#define UNUSED __attribute__((unused))
#define EXPORT __attribute__((visibility("default")))

static inline bool size_mul_overflow(size_t a, size_t b, size_t *result) {
#if defined(__clang__) || __GNUC__ >= 5
#if INTPTR_MAX == INT32_MAX
    return __builtin_umul_overflow(a, b, result);
#else
    return __builtin_umull_overflow(a, b, result);
#endif
#else
    *result = a * b;
    return a && *result / a != b;
#endif
}

#endif

#ifndef UTIL_H
#define UTIL_H

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#undef assert
#ifdef NDEBUG
#define assert(expr) ((void)0)
#else
#define assert(expr) (likely(expr) ? (void)0 : abort())
#endif

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#define UNUSED __attribute__((unused))
#define EXPORT __attribute__((visibility("default")))
#define COLD __attribute__((cold))

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

static inline size_t size_log2(size_t x) {
#if INTPTR_MAX == INT32_MAX
    return 31 - __builtin_clz(x);
#else
    return 63 - __builtin_clzll(x);
#endif
}

#endif

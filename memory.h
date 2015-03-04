#ifndef MEMORY_H
#define MEMORY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define CACHELINE 64

// Return the smallest alignment multiple that is >= s.
#define ALIGNMENT_CEILING(s, alignment) (((s) + (alignment - 1)) & (-(alignment)))

// Return the nearest aligned address at or below a.
#define ALIGNMENT_ADDR2BASE(a, alignment) ((void *)((uintptr_t)(a) & (-(alignment))))

// Return the offset between a and the nearest aligned address at or below a.
#define ALIGNMENT_ADDR2OFFSET(a, alignment) ((size_t)((uintptr_t)(a) & (alignment - 1)))

#define PAGE_SIZE ((size_t)4096)
#define PAGE_MASK ((size_t)(PAGE_SIZE - 1))

// Return the smallest page size multiple that is >= s.
#define PAGE_CEILING(s) (((s) + PAGE_MASK) & ~PAGE_MASK)

void memory_init(void);
void memory_decommit(void *ptr, size_t size);
bool memory_commit(void *ptr, size_t size);
void *memory_map(void *hint, size_t size, bool commit);
void *memory_map_aligned(void *hint, size_t size, size_t alignment, bool commit);
void memory_unmap(void *ptr, size_t size);
bool memory_remap_fixed(void *addr, size_t old_size, void *new_addr, size_t new_size);

#endif

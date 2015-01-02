#include <sys/mman.h>

#include "memory.h"

void memory_purge(void *addr, size_t size) {
    madvise(addr, size, MADV_DONTNEED);
}

void *memory_map(void *hint, size_t size) {
    void *addr = mmap(hint, size, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    if (addr == MAP_FAILED) {
        return NULL;
    }
    return addr;
}

void *memory_map_aligned(void *hint, size_t size, size_t alignment) {
    size_t alloc_size = size + alignment - PAGE_SIZE;
    if (alloc_size < size) {
        return NULL;
    }
    void *addr = memory_map(hint, alloc_size);
    if (!addr) {
        return NULL;
    }
    size_t lead_size = ALIGNMENT_CEILING((uintptr_t)addr, alignment) - (uintptr_t)addr;
    size_t trail_size = alloc_size - lead_size - size;
    void *base = (char *)addr + lead_size;
    if (lead_size) {
        munmap(addr, lead_size);
    }
    if (trail_size) {
        munmap((char *)base + size, trail_size);
    }
    return base;
}

void memory_unmap(void *addr, size_t size) {
    munmap(addr, size);
}

bool memory_remap_fixed(void *addr, size_t old_size, void *new_addr, size_t new_size) {
    return mremap(addr, old_size, new_size, MREMAP_MAYMOVE|MREMAP_FIXED, new_addr) == MAP_FAILED;
}

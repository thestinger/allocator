#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "memory.h"

// use MAP_NORESERVE to get either proper memory accounting or full overcommit
static const int map_flags = MAP_ANONYMOUS|MAP_PRIVATE|MAP_NORESERVE;
static bool reduce_commit_charge = true;

void memory_init(void) {
    int overcommit = open("/proc/sys/vm/overcommit_memory", O_RDONLY|O_CLOEXEC);
    if (overcommit != -1) {
        char digit;
        int rc = TEMP_FAILURE_RETRY(read(overcommit, &digit, 1));
        if (rc == 1 && digit != '2') {
            reduce_commit_charge = false;
        }
        close(overcommit);
    }
}

void memory_decommit(void *addr, size_t size) {
    if (reduce_commit_charge) {
        mmap(addr, size, PROT_NONE, map_flags|MAP_FIXED, -1, 0);
    } else {
        madvise(addr, size, MADV_DONTNEED);
    }
}

bool memory_commit(void *addr, size_t size) {
    if (reduce_commit_charge) {
        return mprotect(addr, size, PROT_READ|PROT_WRITE);
    }
    return false;
}

void *memory_map(void *hint, size_t size, bool commit) {
    int prot = !commit && reduce_commit_charge ? PROT_NONE : PROT_READ|PROT_WRITE;
    void *addr = mmap(hint, size, prot, map_flags, -1, 0);
    if (addr == MAP_FAILED) {
        return NULL;
    }
    return addr;
}

void *memory_map_aligned(void *hint, size_t size, size_t alignment, bool commit) {
    size_t alloc_size = size + alignment - PAGE_SIZE;
    if (alloc_size < size) {
        return NULL;
    }
    void *addr = memory_map(hint, alloc_size, commit);
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

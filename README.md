## Current implementation

### Low-level memory management

Chunks are the fundamental building block for all memory allocations. In the
current implementation, the chunks are 4MiB blocks with 4MiB alignment.

Rather than unmapping chunks, extents of free chunks are managed in userspace
to reduce fragmentation, system call overhead and synchronization.

Extents of free chunks are managed via address-ordered best-fit, which greatly
reduces overall fragmentation and provides logarithmic time complexity for
every case where the peak virtual memory doesn't need to be increased. A node
is used to represent each extent, with one intrusive tree for keyed by (size,
address) for allocation and another keyed by address for coalescing.

If there is no address space resource limit, a large portion of the address
space is reserved up-front for a stronger time complexity guarantee and more
compaction from the address ordering. The reserved memory is partitioned
between each core for parallel chunk allocation, falling back to the global
data structure only when it runs out. On 64-bit, this means that there are no
global resources preventing linear scaling as the reserved mapping is enormous.

The system calls for managing mappings (mmap, mprotect, munmap) require taking
the global mmap_sem lock as writers, while page faults and madvise purging use
concurrent reader access. Doing the work in userspace avoids getting in the way
of page faults and is significantly cheaper.

The Linux kernel also lacks an ordering by size, so it has to use an ugly
heuristic for allocation rather than best-fit. It allocates below the lowest
mapping so far if there and room and then falls back to an O(n) scan. This
leaves behind gaps when anything but the lowest mapping is freed, increasing
the rate of TLB misses.

Natural alignment for chunks provides the ability to distinguish between
allocations smaller and larger than the chunk size from the addresses, which
leads to the ability to find metadata in O(1) time. Note that it is currently
O(log n) for huge allocations, but it doesn't have to be. As long as the chunk
size remains a multiple of the transparent huge page size (2MiB), there is also
the benefit of huge pages being able to back every allocation.

### Decommit / purging

When overcommit is enabled, memory is released back to the operating system
with MADV_FREE, or MADV_DONTNEED if the superior lazy MADV_FREE is unavailable.

When overcommit is disabled, commit charge is dropped by setting PROT_NONE on
the mappings in addition to purging.

The ability to opt-in to lightweight purging even without overcommit enabled or
to disable purging completely will be exposed in the future.

On Windows, the usage of PROT_NONE maps directly to MEM_COMMIT and MEM_DECOMMIT
while MADV_FREE is the same as MEM_RESET.

Purging is currently only implemented at a chunk level and does not perform the
work lazily (beyond MADV_FREE lazily dropping pages). The intention is to track
dirty prefixes in free spans of memory, with lazy purging in FIFO order. The
same purging strategy can be used for small, large and chunk allocation.

There will be a minimum permitted amount of dirty memory per-arena before
purging is used along with a ratio of active:dirty pages.

Coalescing a freed span with a free span succeeding it will be painless, while
coalescing with a preceding span that is not entirely dirty will need to use a
heuristic to choose between considering the whole span dirty or purging the new
space and leaving it clean. The address-ordered best-fit algorithm plays well
with dirty prefixes because spans with lower addresses are preferred. Using
first-fit would likely synergize even more, but at the expense of increasing
fragmentation which is what this design tries to avoid in the first place.

The alternative would be segregating clean and dirty memory entirely, but this
would create a new form of fragmentation. It may be tested in the future, but
it is expected that the chosen design will be faster overall without the need
to pay the cost of fragmenting the memory. Tracking the dirty spans could be
done precisely without segregating the memory, but it would be more complex and
more time would be spent managing metadata.

### Rest of the implementation

- major allocation classes:
    - huge: spans of chunks, always chunk-aligned
    - small/large: managed within chunks, never chunk-aligned

- arenas:
    - assign chunks to per-core arenas
    - pick a preferred arena with sched_getcpu and update it on contention
    - separate chunks for small/large, distinguished via chunk header flag
    - per-arena cache of the most recently freed chunk(s)

- large allocations:
    - allocation headers for freeing allocations and coalescing:
        - find the next span with `addr + size` for forward coalescing
        - maintain a pointer to the previous span for backward coalescing
        - spans must be a multiple of the header size, which is 4x pointer-size
        - headers act as spacers and prevent false sharing with 64-bit pointers
          and 64 byte cachelines
    - intrusive tree keyed by (size, addr) for address-ordered best-fit
        - the span headers are the tree nodes
    - chunks are released when a free span covers the entire usable area

- small allocations:
    - per-arena slab LIFO free lists:
        - empty slabs
        - partially filled slabs: doubly-linked list per size class
        - empty slabs are returned to the empty slab list
    - per-slab LIFO free list
    - per-thread LIFO free list

## Future improvements

See the issue tracker.

## Current implementation

- low-memory memory management:
    - naturally aligned chunks as the fundamental building block
    - virtual memory managed in userspace to reduce fragmentation and overhead:
        - memory is purged with MADV_FREE/MADV_DONTNEED rather than unmapping
        - if overcommit is disabled, commit charge is dropped via PROT_NONE
    - node for each span of free chunks:
        - intrusive tree ordered by (size, addr) for address-ordered best-fit
        - intrusive tree ordered by (addr,) for coalescing

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
    - intrusive tree keyed by (size, addr) for address-ordered best-fit
        - the span headers are the tree nodes, making them 4x pointer size
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

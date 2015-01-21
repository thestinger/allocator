- low-memory memory management:
    - naturally aligned chunks as the fundamental building block
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

- large allocations:
    - allocation headers for freeing allocations and coalescing:
        - find the next span with `addr + size` for forward coalescing
        - maintain a pointer to the previous span for backward coalescing
    - intrusive tree keyed by (size, addr) for address-ordered best-fit
        - the span headers are the tree nodes, making them 4x pointer size
    - potentially a small thread-local cache of free spans

- small allocations:
    - per-arena slab LIFO queues:
        - one for empty slabs
        - per size class for partially filled slabs
    - per-slab LIFO queue
    - per-thread LIFO queue

- reducing cache aliasing:
    - randomize the starting offset in slabs using slack space
    - randomize the starting offset in slab chunks using slack space

- releasing memory:
    - improves the common case, but not the worst case
    - should be optional for performance reasons
    - many places where this can be done:
        - returning small allocation chunks to the recycler
        - returning large allocation chunks to the recycler
        - returning slabs with an assigned size class to the empty queue
        - purging spans of empty slabs
        - purging empty large allocation spans
        - purging spans of empty chunks
        - purging when shrinking huge allocations
    - 2 options for reducing commit charge if overcommit is disabled:
        - unmap spans of empty chunks instead of purging (causes VM fragmentation)
        - set PROT_NONE on spans of empty chunks after purging

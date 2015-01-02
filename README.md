- low-memory memory management:
    - naturally aligned chunks as the fundamental building block
    - address-ordered best-fit chunk recycling:
        - one tree ordered by (size, addr)
        - one tree ordered by (addr,)

- major allocation classes:
    - huge: spans of chunks, always chunk-aligned
    - small/large: managed within chunks, never chunk-aligned

- arenas:
    - assign chunks to per-core arenas
    - separate arenas for small/large, distinguished via chunk header flag
    - pick a preferred arena with sched_getcpu and update it on contention

- large allocations:
    - use allocation headers for the size
    - address-ordered best-fit across the arena chunks:
        - could avoid the addr tree using a list through the headers
    - potentially a small cache of free spans in an array

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
        - unmapping spans of empty chunks

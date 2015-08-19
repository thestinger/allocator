#ifndef ARENA_H
#define ARENA_H

#define RB_COMPACT

#include <stdalign.h>

#include "chunk.h"
#include "memory.h"
#include "mutex.h"
#include "rb.h"

#define N_CLASS 32

struct large {
    size_t size;
    void *prev;
    rb_node(struct large) link_size_addr;
    max_align_t data[];
};

typedef rb_tree(struct large) large_tree;
rb_proto(, large_tree_size_addr_, large_tree, struct large)

struct slot {
    struct slot *next;
    uint8_t data[];
};

struct slab {
    struct slab *next;
    struct slab *prev;

    size_t size;
    struct slot *next_slot;
    struct slot *end;

    uint16_t count;
    uint8_t data[];
};

struct chunk {
    int arena;
    bool small;
    max_align_t data[];
};

struct arena {
    alignas(CACHELINE) mutex mutex;

    // last thread to allocate from the arena
    atomic_uintptr_t owner;

    // intrusive singly-linked list
    struct slab *free_slab;

    // intrusive circular doubly-linked list, with this sentinel node at both ends
    struct slab partial_slab[N_CLASS];

    large_tree large_size_addr;
    struct chunk *free_chunk;

    struct chunk_recycler chunks;
    void *chunks_start;
    void *chunks_end;

    struct extent_node *huge_nodes;
    extent_tree huge;
};

struct thread_cache {
    struct slot *bin[N_CLASS];
    size_t bin_size[N_CLASS];
    int arena_index; // -1 if uninitialized
    bool dead; // true if destroyed or uninitialized
};

struct arena *get_huge_arena(void *ptr);
struct arena *get_arena(struct thread_cache *cache);

#endif

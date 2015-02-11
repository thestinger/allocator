#ifndef EXTENT_H
#define EXTENT_H

#define RB_COMPACT

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

#include "rb.h"

struct extent_node {
    union {
        struct {
            void *addr;
            size_t size;
            rb_node(struct extent_node) link_size_addr;
            rb_node(struct extent_node) link_addr;
        };
        struct extent_node *next;
    };
};

typedef rb_tree(struct extent_node) extent_tree;
rb_proto(, extent_tree_szad_, extent_tree, struct extent_node)
rb_proto(, extent_tree_ad_, extent_tree, struct extent_node)

struct extent_node *node_alloc(struct extent_node **free_nodes);
void node_free(struct extent_node **free_nodes, struct extent_node *node);

#endif

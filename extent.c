#include <stdalign.h>

#include "bump.h"
#include "extent.h"
#include "mutex.h"

static int extent_ad_comp(struct extent_node *a, struct extent_node *b) {
    uintptr_t a_addr = (uintptr_t)a->addr;
    uintptr_t b_addr = (uintptr_t)b->addr;
    return (a_addr > b_addr) - (a_addr < b_addr);
}

/* Generate red-black tree functions. */
rb_gen(, extent_tree_ad_, extent_tree, struct extent_node, link_addr, extent_ad_comp)

static int extent_szad_comp(struct extent_node *a, struct extent_node *b) {
    size_t a_size = a->size;
    size_t b_size = b->size;

    int ret = (a_size > b_size) - (a_size < b_size);
    if (ret) {
        return ret;
    }

    return extent_ad_comp(a, b);
}

/* Generate red-black tree functions. */
rb_gen(, extent_tree_szad_, extent_tree, struct extent_node, link_size_addr, extent_szad_comp)

struct extent_node *node_alloc(struct extent_node **free_nodes) {
    if (*free_nodes) {
        struct extent_node *node = *free_nodes;
        *free_nodes = node->next;
        return node;
    }
    return bump_alloc(sizeof(struct extent_node), alignof(struct extent_node));
}

void node_free(struct extent_node **free_nodes, struct extent_node *node) {
    node->next = *free_nodes;
    *free_nodes = node;
}

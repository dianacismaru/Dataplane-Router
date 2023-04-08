#include "iptrie.h"

extern struct route_table_entry *rtable;
extern int rtable_len;

extern TrieNode *root;

/* Count how many bits are set in a mask */
int count_bits_set(uint32_t mask) {
    int count = 0;
    while (mask) {
        count += mask & 1;
        mask >>= 1;
    }
    return count;
}

TrieNode *create_node() {
    TrieNode *new_node = malloc(sizeof(TrieNode));
    new_node->bit0 = NULL;
    new_node->bit1 = NULL;
    new_node->entry_index = -1;

    return new_node;
}

void insert(uint32_t ip_address, uint32_t mask, int index) {
    int bits_set = count_bits_set(ntohl(mask));
    
    // vreau sa adaug doar partea prefixata din host order
    ip_address = ntohl(ip_address) >> (32 - bits_set);

    TrieNode* current_node = root;
    int i;

    for (i = bits_set - 1; i >= 0; i--) {
        int bit = (ip_address >> i) & 1;

        if (bit) {
            if (!current_node->bit1)
                current_node->bit1 = create_node();
            current_node = current_node->bit1;
        } else {
            if (!current_node->bit0)
                current_node->bit0 = create_node();
            current_node = current_node->bit0;
        }
    }   

    current_node->entry_index = index;
}

TrieNode *create_ip_trie() {
    root = create_node();

    for (int i = 0; i < rtable_len; i++) {
        struct route_table_entry entry = rtable[i];
        insert(entry.prefix, entry.mask, i);
    }

    return root;
}

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

/* Create a Trie Node for the IP Trie */
TrieNode *create_node() {
    TrieNode *new_node = malloc(sizeof(TrieNode));
    new_node->bit0 = NULL;
    new_node->bit1 = NULL;
    new_node->entry_index = -1;

    return new_node;
}

/* Insert a prefix in the Trie */
void insert(uint32_t ip_address, uint32_t mask, int index) {
    int bits_set = count_bits_set(ntohl(mask));
    
    /* Add only the prefixed part from Host Order IP address */
    ip_address = ntohl(ip_address) >> (32 - bits_set);

    TrieNode* current_node = root;

    for (int i = bits_set - 1; i >= 0; i--) {
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

    /* At the end of the sequence, store the entry index */
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

void free_trienode(TrieNode* node) {
    if (node->bit0) {
        free_trienode(node->bit0);
    }
    
    if (node->bit1) {
        free_trienode(node->bit1);
    }

    free(node);
}

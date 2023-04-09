#ifndef _IPTRIE_H
#define _IPTRIE_H

#include "utils.h"

typedef struct TrieNode {
    struct TrieNode *bit0;
    struct TrieNode *bit1;
    int entry_index;
} TrieNode;

extern int count_bits_set(uint32_t prefix);

extern TrieNode *create_node();

extern void insert(uint32_t ip_address, uint32_t mask, int index);

extern TrieNode *create_ip_trie();

extern void free_trienode(TrieNode* node);

#endif /* _IPTRIE_H */

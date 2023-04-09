#ifndef _IPTRIE_H
#define _IPTRIE_H

#include "utils.h"

typedef struct TrieNode {
    struct TrieNode *bit0;
    struct TrieNode *bit1;
    int entry_index;
} TrieNode;

/* Count how many bits are set in a mask */
extern int count_bits_set(uint32_t prefix);

/* Create a Trie Node for the IP Trie */
extern TrieNode *create_node();

/* Insert a prefix in the Trie */
extern void insert(uint32_t ip_address, uint32_t mask, int index);

/* Parse the routing table and add each entry in the IP Trie */
extern TrieNode *create_ip_trie();

/* Free the IP Trie recursively */
extern void free_trienode(TrieNode* node);

#endif /* _IPTRIE_H */

#include "utils.h"
#include "iptrie.h"

extern struct route_table_entry *rtable;
extern int rtable_len;

extern struct arp_entry *arp_table;
extern int arptable_len;

extern TrieNode *root;

struct route_table_entry *get_best_route(uint32_t ip_dest) {
    ip_dest = ntohl(ip_dest);

    TrieNode* current = root;
    TrieNode* prev = NULL;

    uint32_t prefix = 0;
    for (int i = 31; i >= 0 && current != NULL; i--) {
        int bit = (ip_dest >> i) & 1;
        prev = current;

        if (bit) {
            current = current->bit1;
        } else {
            current = current->bit0;
        }

        if (current) {
            // adaug bitul la prefix
            prefix |= (bit << i);
        }
    }

    return &rtable[prev->entry_index];
}

struct arp_entry *get_arp_entry(uint32_t given_ip) {
	for (int i = 0; i < arptable_len; i++) {
		if (arp_table[i].ip == given_ip) {
			return &arp_table[i];
		}
	}

	return NULL;
}

struct queued_packet copy_packet(char *buf, size_t len, int interface) {
	struct queued_packet new_packet;

	memcpy(new_packet.data, buf, len);
    new_packet.len = len;
    new_packet.interface = interface;

	return new_packet;
}

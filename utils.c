#include "utils.h"
#include "iptrie.h"

extern struct route_table_entry *rtable;

extern struct arp_entry *arp_table;
extern int arptable_len;

extern TrieNode *root;

extern queue q;

struct route_table_entry *get_best_route(uint32_t ip_dest) {
    ip_dest = ntohl(ip_dest);

    TrieNode* current = root;
    TrieNode* prev = NULL;

    for (int i = 31; i >= 0 && current != NULL; i--) {
        int bit = (ip_dest >> i) & 1;
        prev = current;

        if (bit) {
            current = current->bit1;
        } else {
            current = current->bit0;
        }
    }

    if (prev->entry_index == -1)
        return NULL;
    
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

void parse_cache() {
	queue new_q = queue_create();

	while (!queue_empty(q)) {
		char *packet = (char *)queue_deq(q);

		struct ether_header *eth_hdr = (struct ether_header *)packet;
		struct iphdr *ip_hdr = (struct iphdr *)(packet + ETHER_LEN);

		struct route_table_entry *new_route = get_best_route(ip_hdr->daddr);
		struct arp_entry *arp_entry = get_arp_entry(new_route->next_hop);

		/* If there is an existing entry in the cache, send the packet */
		if (arp_entry) {
			memcpy(eth_hdr->ether_dhost, arp_entry->mac, 6);
			get_interface_mac(new_route->interface, eth_hdr->ether_shost);
			send_to_link(new_route->interface, packet, IP_PACKET_LEN);
		} else {
			queue_enq(new_q, packet);
		}
	}
	q = new_q;
}

void arp_request(char *buf, struct route_table_entry *route_table_entry) {
	char packet[MAX_PACKET_LEN];
	memcpy(packet, buf, IP_PACKET_LEN);

	queue_enq(q, packet);

	struct ether_header *eth_hdr = (struct ether_header *) buf;
	struct arp_header *arp_hdr = (struct arp_header *) (buf + ETHER_LEN);

	// Ethernet Header
	eth_hdr->ether_type = htons(ETHERTYPE_ARP);

	// Mac source
	get_interface_mac(route_table_entry->interface, eth_hdr->ether_shost);

	// MAC destination = Broadcast address
	uint8_t broadcast_addr[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	memcpy(eth_hdr->ether_dhost, broadcast_addr, 6);

	// ARP Header
	arp_hdr->htype = htons(1);
	arp_hdr->ptype = htons(ETHERTYPE_IP);
	arp_hdr->hlen = 6;
	arp_hdr->plen = 4;
	arp_hdr->op = htons(1);

	// Sender IP address
	arp_hdr->spa = inet_addr(get_interface_ip(route_table_entry->interface));

	// Sender MAC address
	get_interface_mac(route_table_entry->interface, arp_hdr->sha);

	// Target MAC address
	uint8_t dest_mac_addr[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	memcpy(arp_hdr->tha, dest_mac_addr, 6);

	// Target IP address
	arp_hdr->tpa = route_table_entry->next_hop;
	
	send_to_link(route_table_entry->interface, buf, ARP_PACKET_LEN);
}

void arp_reply(char *buf, int interface) {
	struct ether_header *eth_hdr = (struct ether_header *) buf;
	struct arp_header *arp_hdr = (struct arp_header *)(buf + ETHER_LEN);

	// Ethernet Header
	eth_hdr->ether_type = htons(ETHERTYPE_ARP);
	
	// MAC destination
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);

	// Mac source
    get_interface_mac(interface, eth_hdr->ether_shost);

	// Operation type
	arp_hdr->op = htons(2);

	// Target MAC address
	memcpy(arp_hdr->tha, arp_hdr->sha, 6);

	// Sender MAC address
	get_interface_mac(interface, arp_hdr->sha);

	// Swap the sender IP address with the target IP addres
	uint32_t tmp = arp_hdr->tpa;
	arp_hdr->tpa = arp_hdr->spa;
	arp_hdr->spa = tmp;
}

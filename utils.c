#include "utils.h"
#include "iptrie.h"

extern struct route_table_entry *rtable;

extern struct arp_entry *arp_table;
extern int arptable_len;

extern TrieNode *root;

extern queue q;

/* Calculate LPM in the IP Trie */
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

/* Parse the ARP table and get the entry corresponding the given IP address */
struct arp_entry *get_arp_entry(uint32_t given_ip) {
	for (int i = 0; i < arptable_len; i++) {
		if (arp_table[i].ip == given_ip) {
			return &arp_table[i];
		}
	}

	return NULL;
}

/* Parse the queue and send the packets that have found the MAC destinations */
void parse_cache() {
	queue new_q = queue_create();

	while (!queue_empty(q)) {
		queued_packet *p = (queued_packet *)queue_deq(q);

		struct ether_header *eth_hdr = (struct ether_header *) (p->data);
		struct iphdr *ip_hdr = (struct iphdr *)(p->data + ETHER_LEN);

		struct route_table_entry *new_route = get_best_route(ip_hdr->daddr);
		struct arp_entry *arp_entry = get_arp_entry(new_route->next_hop);

		/* Skip the packet if the entry was not yet found */
		if (!arp_entry) {
			queue_enq(new_q, p);
		} else {
			/* If there is an existing entry in the cache, send the packet */
			memcpy(eth_hdr->ether_dhost, arp_entry->mac, 6);
			get_interface_mac(new_route->interface, eth_hdr->ether_shost);
			send_to_link(new_route->interface, p->data, p->len);
		}
	}

	/* Restore the queue */
	while (!queue_empty(new_q)) {
		queued_packet *p = (queued_packet *)(queue_deq(new_q));
		queue_enq(q, &p);
	}
}

/* Send an ARP Request */
void arp_request(char *buf, struct route_table_entry *route_table_entry) {
	struct ether_header *eth_hdr = (struct ether_header *) buf;
	struct arp_header *arp_hdr = (struct arp_header *) (buf + ETHER_LEN);

	queued_packet p;
	p.len = ARP_PACKET_LEN;
	memcpy(p.data, buf, ARP_PACKET_LEN);

	queue_enq(q, &p);

	// Ethernet Header
	eth_hdr->ether_type = htons(ETHERTYPE_ARP);

	// Mac source
	get_interface_mac(route_table_entry->interface, eth_hdr->ether_shost);

	// MAC destination = Broadcast address
    hwaddr_aton("ff:ff:ff:ff:ff:ff", eth_hdr->ether_dhost);

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
    hwaddr_aton("00:00:00:00:00:00", arp_hdr->tha);

	// Target IP address
	arp_hdr->tpa = route_table_entry->next_hop;
	
	send_to_link(route_table_entry->interface, buf, ARP_PACKET_LEN);
}

/* Send an ARP Reply */
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

/* Send an ICMP message depending on the givem type */
void send_icmp(char *buf, int interface, uint8_t type) {
    struct ether_header *eth_hdr = (struct ether_header *) buf;
    struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
    struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + IP_PACKET_LEN);

    /* Ethernet Header */
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
	get_interface_mac(interface, eth_hdr->ether_shost);
	
    /* IP Header */
    ip_hdr->version = 4;
	ip_hdr->ihl = 5;
	ip_hdr->tos = 0;
	ip_hdr->protocol = IPPROTO_ICMP;
	ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	ip_hdr->id = htons(1);
	ip_hdr->frag_off = 0;
	ip_hdr->ttl = 64;
	ip_hdr->check = 0;
	ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

	uint32_t tmp = ip_hdr->daddr;
	ip_hdr->daddr = ip_hdr->saddr;
	ip_hdr->saddr = tmp;

    /* ICMP Header */
	icmp_hdr->type = type;
	icmp_hdr->code = 0;
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr)));

	send_to_link(interface, buf, IP_PACKET_LEN + sizeof(struct icmphdr));
}

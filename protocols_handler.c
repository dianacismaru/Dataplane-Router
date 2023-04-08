#include "protocols_handler.h"

extern struct arp_entry *arp_table;
extern int arptable_len;

extern queue q;

void print_mac_address(uint8_t* mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_ip_address(int32_t ip) {
    struct in_addr addr;
    addr.s_addr = ip;
    printf("%s\n", inet_ntoa(addr));
}

int ip(struct ether_header *eth_hdr, struct route_table_entry **route_table_entry, char *buf) {
	/* Check the destination */
	struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

	// merge doar daca iphdr protocol e 1
	// struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));

    uint16_t checksum_tmp = ntohs(ip_hdr->check);
    ip_hdr->check = 0;
    ip_hdr->check = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));

    if (ip_hdr->check != checksum_tmp) {
        printf("Incorrect checksum\n");
        return 1;
    }

    *route_table_entry = get_best_route(ip_hdr->daddr);
    if (!(*route_table_entry)) {
        printf("Destination unreachable\n");
		// TRIMITE ICMP MSG
        return 1;
    }


    if (ip_hdr->ttl <= 1) {
        printf("Time exceeded\n");
		// TRIMITE ICMP MSG
        return 1;
    }

    ip_hdr->ttl--;
    ip_hdr->check = 0;
    ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

		printf("IP_HEADER: \n-------------------\n");
		printf("Source IP: ");
		print_ip_address(ip_hdr->saddr);
		printf("Destination IP: ");
		print_ip_address(ip_hdr->daddr);


    struct arp_entry *arp_entry = get_arp_entry((*route_table_entry)->next_hop);
    // struct arp_entry *arp_entry = get_arp_entry(ip_hdr->daddr);

    if (!arp_entry) {
			printf("ACUM SE VA FACE UN REQUEST\n");
		// create an arp request
		size_t request_len = sizeof(struct ether_header) + sizeof(struct arp_header);
		char *request = arp_request(*route_table_entry);
		send_to_link((*route_table_entry)->interface, request, request_len);

		// trebuie sa adaug pachetul in coada
		struct queued_packet queued_packet = copy_packet(buf, request_len, 
											 (*route_table_entry)->interface);
		queue_enq(q, &queued_packet);

        return 1;
    }

    get_interface_mac((*route_table_entry)->interface, eth_hdr->ether_shost);
    memcpy(eth_hdr->ether_dhost, arp_entry->mac, sizeof(eth_hdr->ether_dhost));

		printf("ETHERNET_HEADER: \n-------------------\n");
		printf("Source MAC: ");
		print_mac_address(eth_hdr->ether_shost);
		printf("Destination MAC: ");
		print_mac_address(eth_hdr->ether_dhost);
		printf("Interface: %d \n", (*route_table_entry)->interface);
		printf("\n\n");
		
    return 0;
}

void arp(struct ether_header *eth_hdr, struct route_table_entry **route_table_entry, char *buf) {
	struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));
	uint16_t op = ntohs(arp_hdr->op);
	size_t len = sizeof(struct ether_header) + sizeof(struct arp_header);

	// Check if there's an ongoing request
	if (op == 1) {
			printf("AM AJUNS PE RAMURA OP 1\n");
		char *reply = arp_reply(buf, *route_table_entry);
		// size_t reply_len = sizeof(struct ether_header) + sizeof(struct arp_header);
			printf("AM AJUNS SA DAU SEND SAU SAL?\n");
		
		send_to_link((*route_table_entry)->interface, reply, len);
		// trebuie un free la reply
	} 
	// Check if there's an ongoing reply 
	else if (/*arp_hdr->tpa == inet_addr(get_interface_ip((*route_table_entry)->interface))
			 && */ op == 2) {
			printf("AM AJUNS PE RAMURA OP 2\n");

		// Add the packet to the local cache
		struct arp_entry new_entry;

		new_entry.ip = arp_hdr->spa;
		memcpy(new_entry.mac, arp_hdr->sha, 6); // sau eth hdr -> shost?
		arp_table[arptable_len++] = new_entry;

		// Check the queue element by element
		queue new_q = queue_create();
		while (!queue_empty(q)) {
			struct queued_packet *packet = (struct queued_packet *)(queue_deq(q));
			struct iphdr *ip_hdr = (struct iphdr *)(packet->data + sizeof(struct ether_header));

			struct route_table_entry* new_route = get_best_route(ip_hdr->daddr);
			struct arp_entry *arp_entry = get_arp_entry(new_route->next_hop);

			// If there is an existing entry in the cache, send the packet
			if (arp_entry) {
				struct ether_header *eth_hdr = (struct ether_header *)packet->data;
				memcpy(eth_hdr->ether_dhost, arp_entry->mac, 6);
				get_interface_mac(new_route->interface, eth_hdr->ether_shost);
				send_to_link(packet->interface, packet->data, packet->len);
			} else {
				queue_enq(q, packet);
			}
		}

		// Restore the queue
		while (!queue_empty(new_q)) {
			struct queued_packet *packet = (struct queued_packet *)(queue_deq(new_q));
			queue_enq(q, packet);
		}
	}/* else {
			printf("AM PRIMIT UN REPLY, DAR NU ESTE PENTRU MINE, TREBUIE SA IL DAU MAI DEPARTE\n");

			struct route_table_entry *route_table_entry = get_best_route(arp_hdr->tpa);
			send_to_link(route_table_entry->interface, buf, len);
	}*/
}

/* 
* Make an ARP request if the ARP entry was not found
*/
char *arp_request(struct route_table_entry *route_table_entry) {
	// Create a packet with Ethernet header and with ARP header
	char *request = calloc(MAX_PACKET_LEN, 1);
	struct ether_header *eth_hdr = (struct ether_header *) request;
	struct arp_header *arp_hdr = (struct arp_header *) (request + sizeof(struct ether_header));
	// memset(request, 0, sizeof(request));

	// Ethernet Header
	eth_hdr->ether_type = ETHERTYPE_ARP;
	
	// Mac source = adresa interfetei routerului catre next hop
    get_interface_mac(route_table_entry->interface, eth_hdr->ether_shost);

	// MAC destination = Broadcast address
	uint8_t broadcast_addr[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	memcpy(eth_hdr->ether_dhost, broadcast_addr, 6);

	// ARP Header
	arp_hdr->htype = htons(1);
	arp_hdr->ptype = htons(ETHERTYPE_IP);;
	arp_hdr->hlen = 6;
	arp_hdr->plen = 4;
	arp_hdr->op = htons(1);

	// Sender MAC address
	memcpy(arp_hdr->sha, eth_hdr->ether_shost, 6);

	// Sender IP address
	arp_hdr->spa = inet_addr(get_interface_ip(route_table_entry->interface));

	// Target MAC address
	uint8_t dest_mac_addr[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	memcpy(arp_hdr->tha, dest_mac_addr, 6);

	// Target IP address
	arp_hdr->tpa = route_table_entry->next_hop;

	return request;
}

char *arp_reply(char *buf, struct route_table_entry *route_table_entry) {
	struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));
			printf("INTRU IN REPLY\n");
	char *reply = calloc(MAX_PACKET_LEN, 1);
	struct ether_header *new_eth_hdr = (struct ether_header *) reply;
	struct arp_header *new_arp_hdr = (struct arp_header *) (reply + sizeof(struct ether_header));
	// memset(reply, 0, sizeof(reply));
			printf("1\n");

	// Ethernet Header
	new_eth_hdr->ether_type = ETHERTYPE_ARP;
			printf("2\n");
	

	// Mac source
	// TODO: lasa variabila
    get_interface_mac(route_table_entry->interface, new_eth_hdr->ether_shost);
			printf("3\n");

	// MAC destination
	memcpy(new_eth_hdr->ether_dhost, arp_hdr->sha, 6);
			printf("4\n");

	// ARP Header
	new_arp_hdr->htype = htons(1);
	new_arp_hdr->ptype = htons(ETHERTYPE_IP);;
	new_arp_hdr->hlen = 6;
	new_arp_hdr->plen = 4;

	// Operation type
	arp_hdr->op = htons(2);
			printf("5\n");

	// Sender MAC address
	memcpy(new_arp_hdr->sha, new_eth_hdr->ether_shost, 6);
			printf("6\n");

	// Sender IP address
	new_arp_hdr->spa = arp_hdr->tpa;

	// Target MAC address
	memcpy(new_arp_hdr->tha, new_eth_hdr->ether_dhost, 6);
			printf("7\n");

	// Target IP address
	new_arp_hdr->tpa = arp_hdr->spa;
			printf("IES DIN REPLY\n");

	return reply;
}

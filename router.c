/* Copyright (C) 2023 Cismaru Diana-Iuliana (321CA / 2022-2023) */
#include "queue.h"
#include "lib.h"
#include "utils.h"
#include "protocols.h"

#include <string.h>
#include <arpa/inet.h> 

struct route_table_entry *rtable;
int rtable_len;

struct arp_entry *arp_table;
int arptable_len;

queue q;

struct route_table_entry *get_best_route(uint32_t ip_dest);
struct arp_entry *get_arp_entry(uint32_t given_ip);
int ip(struct ether_header *eth_hdr, struct route_table_entry **route_table_entry, char *buf);
void arp(struct ether_header *eth_hdr, struct route_table_entry **route_table_entry, char *buf);
struct queued_packet copy_packet(char *buf, size_t len, int interface);
char *arp_request(struct route_table_entry *route_table_entry);
char *arp_reply(char *buf, struct route_table_entry *route_table_entry);

void print_mac_address(uint8_t* mac);
void print_ip_address(int32_t ip);

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	rtable = malloc(sizeof(struct route_table_entry) * 1000000);
	DIE(rtable == NULL, "memory");
	rtable_len = read_rtable(argv[1], rtable);

	arp_table = malloc(sizeof(struct arp_entry) * 100);
	DIE(arp_table == NULL, "memory");
	arptable_len =  parse_arp_table("arp_table.txt", arp_table);

	q = queue_create();

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		printf("\nA PACKET WAS RECEIVED\n");

		struct route_table_entry *route_table_entry = NULL;

		/* Check if we got an IPv4 packet */
		if (eth_hdr->ether_type == ntohs(ETHERTYPE_IP)) {
			if (ip(eth_hdr, &route_table_entry, buf)) {
				continue;
			}
			send_to_link(route_table_entry->interface, buf, len);
		}
		/* Check if we got an ARP packet */
		else if (eth_hdr->ether_type == ntohs(ETHERTYPE_ARP)) {
			// if (arp(eth_hdr, &route_table_entry, buf)) {
			// 	continue;
			// }
			// arp(eth_hdr, &route_table_entry, buf);
			continue;
		}
		else {
			printf("\nIgnored packet\n");
			continue;
		}
	}
}

struct route_table_entry *get_best_route(uint32_t ip_dest) {
	uint32_t best_mask = 0;
	struct route_table_entry *best_route = NULL;

	for (int i = 0; i < rtable_len; i++) {
		uint32_t current_mask = rtable[i].mask;

		if ((rtable[i].prefix & current_mask) == (ip_dest & current_mask) 
			&& current_mask >= best_mask) {
			best_mask = current_mask;
			best_route = &rtable[i];
		}
	}

	return best_route;
}

struct arp_entry *get_arp_entry(uint32_t given_ip) {
	for (int i = 0; i < arptable_len; i++) {
		if (arp_table[i].ip == given_ip) {
			return &arp_table[i];
		}
	}

	return NULL;
}

int ip(struct ether_header *eth_hdr, struct route_table_entry **route_table_entry, char *buf) {
	/* Check the destination */
	struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

	// merge doar daca iphdr protocol e 1
	struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));

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
    if (!arp_entry) {
		// create an arp request
		size_t request_len = sizeof(struct ether_header) + sizeof(struct arp_header);
		char *request = arp_request(*route_table_entry);
		send_to_link((*route_table_entry)->interface, request, request_len);

		// trebuie sa adaug pachetul in coada
		struct queued_packet queued_packet = copy_packet(buf, request_len, (*route_table_entry)->interface);
		queue_enq(q, &queued_packet);

        printf("There's no MAC address to that destination IP\n");
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

	// Check if there's an ongoing request
	if (op == 1) {
		char *reply = arp_reply(buf, *route_table_entry);
		size_t reply_len = sizeof(struct ether_header) + sizeof(struct arp_header);

		send_to_link((*route_table_entry)->interface, reply, reply_len);
		// trebuie un free la reply
	} // Check if there's an ongoing reply 
	else if (op == 2) {
		// Add the packet to the local cache

		// Check the queue
	}

}

void print_mac_address(uint8_t* mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_ip_address(int32_t ip) {
    struct in_addr addr;
    addr.s_addr = ip;
    printf("%s\n", inet_ntoa(addr));
}

struct queued_packet copy_packet(char *buf, size_t len, int interface) {
	struct queued_packet new_packet;

	memcpy(new_packet.payload, buf, len);
    new_packet.len = len;
    new_packet.interface = interface;

	return new_packet;
}

/* 
* Make an ARP request if the ARP entry was not found
* returns the length of the ARP packet
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

	char *reply = calloc(MAX_PACKET_LEN, 1);
	struct ether_header *new_eth_hdr = (struct ether_header *) reply;
	struct arp_header *new_arp_hdr = (struct arp_header *) (reply + sizeof(struct ether_header));
	// memset(reply, 0, sizeof(reply));

	// Ethernet Header
	new_eth_hdr->ether_type = ETHERTYPE_ARP; // OK
	
	// Mac source
    get_interface_mac(route_table_entry->interface, new_eth_hdr->ether_shost); // OK

	// MAC destination
	memcpy(new_eth_hdr->ether_dhost, arp_hdr->sha, 6); // OK

	// ARP Header
	new_arp_hdr->htype = htons(1);
	new_arp_hdr->ptype = htons(ETHERTYPE_IP);;
	new_arp_hdr->hlen = 6;
	new_arp_hdr->plen = 4;

	// Operation type
	arp_hdr->op = htons(2); // OK

	// Sender MAC address
	memcpy(new_arp_hdr->sha, new_eth_hdr->ether_shost, 6); // OK

	// Sender IP address
	new_arp_hdr->spa = arp_hdr->tpa; // OK

	// Target MAC address
	memcpy(new_arp_hdr->tha, new_eth_hdr->ether_dhost, 6); // OK

	// Target IP address
	new_arp_hdr->tpa = arp_hdr->spa; // OK

	return reply;
}

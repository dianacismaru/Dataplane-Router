/* Copyright (C) 2023 Cismaru Diana-Iuliana (321CA / 2022-2023) */
#include "queue.h"
#include "lib.h"
#include "protocols.h"

#include <string.h>
#include <arpa/inet.h> 

/* IP protocol */
#define ETHERTYPE_IP		0x0800

/* ARP protocol */
#define ETHERTYPE_ARP		0x0806

struct route_table_entry *rtable;
int rtable_len;

struct arp_entry *arp_table;
int arptable_len;

struct route_table_entry *get_best_route(uint32_t ip_dest);
struct arp_entry *get_arp_entry(uint32_t given_ip);
int ip(struct ether_header *eth_hdr, struct iphdr *ip_hdr, struct route_table_entry **route_table_entry);
int arp(struct ether_header *eth_hdr, struct arp_header *arp_hdr);
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

	queue q = queue_create();

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
			struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
			int res = ip(eth_hdr, ip_hdr, &route_table_entry);

			if (res) {
				continue;
			}
			send_to_link(route_table_entry->interface, buf, len);
		}
		/* Check if we got an ARP packet */
		else if (eth_hdr->ether_type == ntohs(ETHERTYPE_ARP)) {
			struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));
			int res = arp(eth_hdr, (struct arp_header *)(buf + sizeof(struct ether_header)));

			if (res) {
				continue;
			}

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

int ip(struct ether_header *eth_hdr, struct iphdr *ip_hdr, struct route_table_entry **route_table_entry) {
    uint16_t checksum_tmp = ntohs(ip_hdr->check);
    ip_hdr->check = 0;
    ip_hdr->check = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));

    if (ip_hdr->check != checksum_tmp) {
        printf("Incorrect checksum\n");
        return 1;
    }

    *route_table_entry = get_best_route(ip_hdr->daddr);
    if (!(*route_table_entry)) {
        printf("There's no route to that destination IP\n");
        return 1;
    }


    if (ip_hdr->ttl < 1) {
        printf("No more Time to Live\n");
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

int arp(struct ether_header *eth_hdr, struct arp_header *arp_hdr) {
    return 1;
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


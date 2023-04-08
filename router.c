/* Copyright (C) 2023 Cismaru Diana-Iuliana (321CA / 2022-2023) */
#include "utils.h"
#include "iptrie.h"
#include "protocols_handler.h"

struct route_table_entry *rtable;
int rtable_len;

TrieNode *root;

struct arp_entry *arp_table;
int arptable_len;

queue q;

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	rtable = malloc(sizeof(struct route_table_entry) * 1000000);
	DIE(rtable == NULL, "memory");
	rtable_len = read_rtable(argv[1], rtable);

	/* Add the route table entries to the Trie*/
	root = create_ip_trie();

	arp_table = malloc(sizeof(struct arp_entry) * 1000000);
	DIE(arp_table == NULL, "memory");
	arptable_len = parse_arp_table("arp_table.txt", arp_table);

	q = queue_create();
	struct route_table_entry *route_table_entry = NULL;

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


		/* Check if we got an IPv4 packet */
		if (eth_hdr->ether_type == ntohs(ETHERTYPE_IP)) {
			printf("AM AJUNS PE IPV4\n");
			if (ip(eth_hdr, &route_table_entry, buf)) {
				// An error has occured, so drop the packet
				continue;
			}
			send_to_link(route_table_entry->interface, buf, len);
		}
		/* Check if we got an ARP packet */
		else if (eth_hdr->ether_type == ntohs(ETHERTYPE_ARP)) {
			printf("AM AJUNS PE ARP\n");
			// arp(eth_hdr, &route_table_entry, buf);
			continue;
		}
		else {
			printf("\nIgnored packet\n");
			continue;
		}
	}
}

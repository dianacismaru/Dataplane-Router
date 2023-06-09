#include <arpa/inet.h>
#include <string.h>
#include "utils.h"
#include "iptrie.h"

/* Routing table */
struct route_table_entry *rtable;
int rtable_len;

/* Mac table */
struct arp_entry *arp_table;
int arptable_len;

TrieNode *root;

queue q;

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	rtable = malloc(sizeof(struct route_table_entry) * MAX_TABLE_LEN);
	DIE(rtable == NULL, "Malloc failed\n");

	arp_table = malloc(sizeof(struct arp_entry) * MAX_TABLE_LEN);
	DIE(arp_table == NULL, "Malloc failed\n");

	rtable_len = read_rtable(argv[1], rtable);
	root = create_ip_trie();

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

		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
			struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

			/* Check if the router is the destination of the received packet and the
			   IP header's protocol is ICMP */
			if (ip_hdr->daddr == inet_addr(get_interface_ip(interface)) && ip_hdr->protocol == IPPROTO_ICMP) {
				struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + IP_PACKET_LEN);

				/* Check if an ECHO REQUEST was received */
				if (icmp_hdr->type == ICMP_ECHOREQ) {
					/* Send an ECHO REPLY */
					send_icmp(buf, interface, ICMP_ECHOREPLY);
				}

				continue;
			}

			uint16_t checksum_tmp = ntohs(ip_hdr->check);
			ip_hdr->check = 0;
			ip_hdr->check = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));

			if (ip_hdr->check != checksum_tmp) {
				continue;
			}

			/* Search for the longest prefix match */
			struct route_table_entry *route_table_entry = get_best_route(ip_hdr->daddr);

			/* If LPM was not found, send an ICMP message */
			if (!route_table_entry) {
				send_icmp(buf, interface, ICMP_DEST_UNREACH);
				continue;
			}

			/* If TTL has expired, send an ICMP message */
			if (ip_hdr->ttl <= 1) {
				send_icmp(buf, interface, ICMP_TIME_EXCEEDED);
				continue;
			}

			ip_hdr->ttl--;
			ip_hdr->check = 0;
			ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

			struct arp_entry *arp_entry = get_arp_entry(route_table_entry->next_hop);

			/* If there's not an arp entry for the next hop, send an ARP Request */
			if (!arp_entry) {
				arp_request(buf, route_table_entry);
				continue;
			}

			get_interface_mac(route_table_entry->interface, eth_hdr->ether_shost);
			memcpy(eth_hdr->ether_dhost, arp_entry->mac, 6);

			send_to_link(route_table_entry->interface, buf, len);
			
		} else if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
			struct arp_header *arp_hdr = (struct arp_header *)(buf + ETHER_LEN);

			/* Check if there's an ongoing request */
			if (htons(arp_hdr->op) == 1 && arp_hdr->tpa == inet_addr(get_interface_ip(interface))) {
				arp_reply(buf, interface);
				send_to_link(interface, buf, ARP_PACKET_LEN);
			}

			/* Check if there's an ongoing reply */
			if (htons(arp_hdr->op) == 2) {
				/* Add the packet to the local cache */
				struct arp_entry new_entry;

				new_entry.ip = arp_hdr->spa;
				memcpy(new_entry.mac, arp_hdr->sha, 6);
				arp_table[arptable_len++] = new_entry;

				parse_queue();
			}
		} else {
			printf("\nIgnored packet\n");
			continue;
		}
	}

	free(arp_table);
	free(rtable);
	free_trienode(root);
}

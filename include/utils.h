#ifndef _UTILS_H
#define _UTILS_H

#include "queue.h"
#include "lib.h"
#include "protocols.h"

#include <string.h>
#include <arpa/inet.h> 

/* IP protocol */
#define ETHERTYPE_IP	0x0800

/* ARP protocol */
#define ETHERTYPE_ARP	0x0806

#define ICMP_ECHOREPLY		0	/* Echo Reply			*/
#define ICMP_DEST_UNREACH	3	/* Destination Unreachable	*/
#define ICMP_ECHOREQ		8	/* Echo Request			*/
#define ICMP_TIME_EXCEEDED	11	/* Time Exceeded		*/

#define ETHER_LEN           sizeof(struct ether_header)
#define IP_PACKET_LEN       sizeof(struct ether_header) + sizeof(struct iphdr)
#define ARP_PACKET_LEN      sizeof(struct ether_header) + sizeof(struct arp_header)

extern struct route_table_entry *get_best_route(uint32_t ip_dest);

extern struct arp_entry *get_arp_entry(uint32_t given_ip);

extern void parse_cache();

extern void arp_request(char *buf, struct route_table_entry *route_table_entry);

extern void arp_reply(char *buf, int interface);

extern void icmp_generate(char *buf, struct ether_header* eth_hdr, struct iphdr *ip_hdr, int interface,  uint8_t type);

#endif /* _UTILS_H_ */

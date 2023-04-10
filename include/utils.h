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

/* Maximum length for routing table and ARP table */
#define MAX_TABLE_LEN   100000

#define ICMP_ECHOREPLY		0	/* Echo Reply			*/
#define ICMP_DEST_UNREACH	3	/* Destination Unreachable	*/
#define ICMP_ECHOREQ		8	/* Echo Request			*/
#define ICMP_TIME_EXCEEDED	11	/* Time Exceeded		*/

#define ETHER_LEN           sizeof(struct ether_header)
#define IP_PACKET_LEN       sizeof(struct ether_header) + sizeof(struct iphdr)
#define ARP_PACKET_LEN      sizeof(struct ether_header) + sizeof(struct arp_header)

/* Packet structure that is stored in the cache */
typedef struct queued_packet {
    size_t len;
    char data[MAX_PACKET_LEN];
} queued_packet;

/* Calculate LPM in the IP Trie */
extern struct route_table_entry *get_best_route(uint32_t ip_dest);

/* Parse the ARP table and get the entry corresponding the given IP address */
extern struct arp_entry *get_arp_entry(uint32_t given_ip);

/* Parse the queue and send the packets that have found the MAC destinations */
extern void parse_queue();

/* Send an ARP Request */
extern void arp_request(char *buf, struct route_table_entry *route_table_entry);

/* Send an ARP Reply */
extern void arp_reply(char *buf, int interface);

/* Send an ICMP message depending on the givem type */
extern void send_icmp(char *buf, int interface, uint8_t type);

#endif /* _UTILS_H_ */

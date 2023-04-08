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

// #define ICMP_ECHOREPLY		0	/* Echo Reply			*/
// #define ICMP_DEST_UNREACH	3	/* Destination Unreachable	*/
// #define ICMP_ECHO		8	/* Echo Request			*/
// #define ICMP_TIME_EXCEEDED	11	/* Time Exceeded		*/

struct queued_packet {
    size_t len;
	char data[MAX_PACKET_LEN];
    int interface;
};

extern struct route_table_entry *get_best_route(uint32_t ip_dest);
extern struct arp_entry *get_arp_entry(uint32_t given_ip);

#endif /* _UTILS_H_ */

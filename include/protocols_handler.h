#ifndef _PROTOCOLS_HANDLER_H
#define _PROTOCOLS_HANDLER_H

#include "utils.h"

extern int ip(struct ether_header *eth_hdr, struct route_table_entry **route_table_entry, char *buf);

extern void arp(struct ether_header *eth_hdr, struct route_table_entry **route_table_entry, char *buf);

/* 
* Make an ARP request if the ARP entry was not found
*/
extern char *arp_request(struct route_table_entry *route_table_entry);

extern char *arp_reply(char *buf, struct route_table_entry *route_table_entry);

#endif /* _PROTOCOLS_HANDLER_H */

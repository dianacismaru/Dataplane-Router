#ifndef _UTILS_H
#define _UTILS_H

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
    int interface;
	char payload[MAX_PACKET_LEN];
};

#endif /* _UTILS_H_ */

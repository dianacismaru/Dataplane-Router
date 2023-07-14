*Copyright (C) 2023 Cismaru Diana-Iuliana (321CA - 2022/2023)*

# Dataplane Router

## Table of Contents
1. [Description of the Project](#1-description-of-the-project)
2. [LPM](#2-lpm)
3. [IPv4 Protocol](#3-ipv4-protocol)
4. [ICMP Protocol](#4-icmp-protocol)
5. [ARP Protocol](#5-arp-protocol)

## 1. Description of the Project
This project implements the process of **forwarding** in a Dataplane Router.
The protocols that are being handled are **IPv4** and **ARP**. The entry point of 
the project is found in `router.c`, in which the Ethernet type is inspected.
All the auxiliary functions are located in `utils.c`.


## 2. LPM
I decided to use a **trie** data structure (implemented in `iptrie.c`) to find
the longest prefix match (LPM).

- Each node of the trie contains two child nodes, one for bit 0, other for bit 1.
The last bit of the prefix stores the index corresponding the prefix to the
routing table.

- I inserted all of the prefixes from the routing table in the trie, but I only
added the number of bits that are set in the mask. For example, for the entry
192.168.1.0/24, I added the first 24 bits of the address. Considering the
maximum depth is 32 nodes, the searh of LPM takes **O(1)**.


## 3. IPv4 Protocol
IPv4 Protocol is identified by *0x0800* ether-type. This part of the project was
the easiest, because it was very much like the 4th laboratory.

- The received packet is dropped if the checksum is corrupted. If the TTL has 
expired or if there is no route available to the destination address, an ICMP
message is sent for each of these situations and the packet is also dropped.
TTL is decremented, so the checksum needs to be recomputed.

- I search in the cache for an ARP entry that matches the next hop's IP. If that
doesn't exist, I generate an ARP request: the current packet is enqueued. For
that, I encapsulated the packet into the structure `queued_packet`, because I
also needed to store the length of the data. Also, the ARP packet has to be
sent to the broadcast address.

- Otherwise, I determine the MAC address and send the packet.

## 4. ICMP Protocol
- When receiving an IPv4 packet, I inspect the contained protocol: if the destination of the packet is actually the router and there is also an ICMP message of type *ECHO REQUEST*, the router has to answer with an ICMP message of type *ECHO REPLY*.

- If the TLL is less than 1, an ICMP message of type *TIME EXCEEDED* is sent.

- If there is not a route to the next top, an ICMP message of *DESTINATION
UNREACHABLE* is sent.


## 5. ARP Protocol
ARP Protocol is identified by *0x0806* ether-type. There are two cases:

1) I receive a **request** (identified by *opcode 1*): the Ethernet header is
updated so that I send a reply with the router's MAC back to the source.

2) I receive a **reply** (identified by *opcode 2*): a new entry is added in the
local cache, and then the queue is parsed. Where MAC address has been found, the
packet is sent to the best route. The rest of the packets remain in the queue.
Because I needed to keep the initial order of the packets in queue, I had to
create a temporary queue.

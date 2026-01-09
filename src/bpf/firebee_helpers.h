#ifndef __FIREBEE_HELPERS_H__
#define __FIREBEE_HELPERS_H__

#include "firebee_common.h"

/*
 * Check if a packet IP matches a rule IP with CIDR support
 * 
 * @packet_ip: IP address from the packet (host byte order)
 * @rule_ip: IP address from the rule (host byte order)
 * @subnet_mask: Subnet mask for CIDR matching
 * 
 * Returns: 1 if match, 0 if no match
 */
static __always_inline int ip_matches(__u32 packet_ip, __u32 rule_ip, __u32 subnet_mask) {
    if (subnet_mask == 0xFFFFFFFF) {
        /* Exact IP match */
        return packet_ip == rule_ip;
    } else if (subnet_mask == 0) {
        /* Match any IP (0.0.0.0/0) */
        return 1;
    } else {
        /* CIDR subnet match */
        return (packet_ip & subnet_mask) == (rule_ip & subnet_mask);
    }
}

/*
 * Check if a packet port matches a rule port
 * 
 * @packet_port: Port from the packet
 * @rule_port: Port from the rule (PORT_ANY for wildcard)
 * 
 * Returns: 1 if match, 0 if no match
 */
static __always_inline int port_matches(__u16 packet_port, __u16 rule_port) {
    return rule_port == PORT_ANY || packet_port == rule_port;
}

/*
 * Check if a packet's protocol matches a rule's protocol
 * 
 * @packet_proto: Protocol from the packet (IPPROTO_TCP, IPPROTO_UDP, etc.)
 * @rule_proto: Protocol from the rule (IPPROTO_ANY for wildcard)
 * 
 * Returns: 1 if match, 0 if no match
 */
static __always_inline int protocol_matches(__u8 packet_proto, __u8 rule_proto) {
    return rule_proto == IPPROTO_ANY || rule_proto == packet_proto;
}

#endif /* __FIREBEE_HELPERS_H__ */

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
        return packet_ip == rule_ip;
    } else if (subnet_mask == 0) {
        return 1;
    } else {
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

/*
 * Check if an IPv6 address matches a rule with prefix length
 * 
 * @packet_ip: IPv6 address from the packet (__u32[4] in network byte order)
 * @rule_ip: IPv6 address from the rule (__u32[4] in network byte order)
 * @prefix_len: Prefix length (0-128)
 * 
 * Returns: 1 if match, 0 if no match
 */
static __always_inline int ipv6_matches(__u32 packet_ip[4], __u32 rule_ip[4], __u8 prefix_len) {
    if (prefix_len == 0) {
        return 1;
    }
    
    if (prefix_len == 128) {
        return packet_ip[0] == rule_ip[0] && 
               packet_ip[1] == rule_ip[1] && 
               packet_ip[2] == rule_ip[2] && 
               packet_ip[3] == rule_ip[3];
    }
    
    __u32 mask;
    
    if (prefix_len >= 32) {
        if (packet_ip[0] != rule_ip[0]) return 0;
    } else {
        mask = bpf_htonl(0xFFFFFFFF << (32 - prefix_len));
        if ((packet_ip[0] & mask) != (rule_ip[0] & mask)) return 0;
        return 1;
    }
    
    if (prefix_len >= 64) {
        if (packet_ip[1] != rule_ip[1]) return 0;
    } else if (prefix_len > 32) {
        mask = bpf_htonl(0xFFFFFFFF << (64 - prefix_len));
        if ((packet_ip[1] & mask) != (rule_ip[1] & mask)) return 0;
        return 1;
    }
    
    if (prefix_len >= 96) {
        if (packet_ip[2] != rule_ip[2]) return 0;
    } else if (prefix_len > 64) {
        mask = bpf_htonl(0xFFFFFFFF << (96 - prefix_len));
        if ((packet_ip[2] & mask) != (rule_ip[2] & mask)) return 0;
        return 1;
    }
    
    if (prefix_len > 96) {
        mask = bpf_htonl(0xFFFFFFFF << (128 - prefix_len));
        if ((packet_ip[3] & mask) != (rule_ip[3] & mask)) return 0;
    }
    
    return 1;
}

#endif /* __FIREBEE_HELPERS_H__ */

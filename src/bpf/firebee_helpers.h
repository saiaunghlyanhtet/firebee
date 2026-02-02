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

/*
 * Extract transport layer ports from IPv4 packet
 * Only applies to TCP and UDP protocols
 */
static __always_inline void extract_ports(
	struct iphdr *iph,
	void *data_end,
	__u8 protocol,
	__u16 *src_port,
	__u16 *dst_port
) {
	*src_port = 0;
	*dst_port = 0;

	void *l4_hdr = (void *)iph + (iph->ihl * 4);

	if (protocol == IPPROTO_TCP) {
		struct tcphdr *tcph = l4_hdr;
		if ((void *)(tcph + 1) > data_end) {
			return;
		}
		*src_port = bpf_ntohs(tcph->source);
		*dst_port = bpf_ntohs(tcph->dest);
	} else if (protocol == IPPROTO_UDP) {
		struct udphdr *udph = l4_hdr;
		if ((void *)(udph + 1) > data_end) {
			return;
		}
		*src_port = bpf_ntohs(udph->source);
		*dst_port = bpf_ntohs(udph->dest);
	}
}

/*
 * Extract transport layer ports from IPv6 packet
 * Only applies to TCP and UDP protocols
 */
static __always_inline void extract_ports_v6(
	struct ipv6hdr *ip6h,
	void *data_end,
	__u8 protocol,
	__u16 *src_port,
	__u16 *dst_port
) {
	*src_port = 0;
	*dst_port = 0;

	void *l4_hdr = (void *)(ip6h + 1);

	if (protocol == IPPROTO_TCP) {
		struct tcphdr *tcph = l4_hdr;
		if ((void *)(tcph + 1) > data_end) {
			return;
		}
		*src_port = bpf_ntohs(tcph->source);
		*dst_port = bpf_ntohs(tcph->dest);
	} else if (protocol == IPPROTO_UDP) {
		struct udphdr *udph = l4_hdr;
		if ((void *)(udph + 1) > data_end) {
			return;
		}
		*src_port = bpf_ntohs(udph->source);
		*dst_port = bpf_ntohs(udph->dest);
	}
}

/*
 * Log packet event to ring buffer for userspace
 */
static __always_inline void log_packet(__u32 ip, __u8 action) {
	struct log_event *event = bpf_ringbuf_reserve(&log_events, sizeof(*event), 0);
	if (event) {
		event->src_ip = ip;
		event->action = action;
		bpf_ringbuf_submit(event, 0);
	}
}

/*
 * Check if packet matches a specific rule
 * Returns 1 if all conditions match, 0 otherwise
 */
static __always_inline int rule_matches(
	struct rule_entry *rule,
	__u32 packet_ip,
	__u8 protocol,
	__u16 src_port,
	__u16 dst_port,
	__u8 packet_direction
) {
	if (rule->direction != DIRECTION_BOTH && rule->direction != packet_direction) {
		return 0;
	}

	if (!ip_matches(packet_ip, rule->src_ip, rule->subnet_mask)) {
		return 0;
	}

	if (!protocol_matches(protocol, rule->protocol)) {
		return 0;
	}

	if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
		if (!port_matches(src_port, rule->src_port)) {
			return 0;
		}
		if (!port_matches(dst_port, rule->dst_port)) {
			return 0;
		}
	}

	return 1;
}

/*
 * Check if IPv6 packet matches a specific rule
 * Returns 1 if all conditions match, 0 otherwise
 */
static __always_inline int rule_matches_v6(
	struct rule_entry_v6 *rule,
	__u32 packet_ip[4],
	__u8 protocol,
	__u16 src_port,
	__u16 dst_port,
	__u8 packet_direction
) {
	if (rule->direction != DIRECTION_BOTH && rule->direction != packet_direction) {
		return 0;
	}

	if (!ipv6_matches(packet_ip, rule->src_ip, rule->prefix_len)) {
		return 0;
	}

	if (!protocol_matches(protocol, rule->protocol)) {
		return 0;
	}

	if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
		if (!port_matches(src_port, rule->src_port)) {
			return 0;
		}
		if (!port_matches(dst_port, rule->dst_port)) {
			return 0;
		}
	}

	return 1;
}

/*
 * Find matching rule for packet and update statistics
 * Returns action (ACTION_ALLOW or ACTION_DROP)
 * First matching rule wins
 * Updates rule_index with the matched rule index (or -1 if no match)
 */
static __always_inline __u8 find_matching_rule(
	__u32 packet_ip,
	__u8 protocol,
	__u16 src_port,
	__u16 dst_port,
	__u8 packet_direction,
	__u32 *rule_index
) {
	__u8 action = ACTION_ALLOW; /* Default: allow */
	__u32 i;
	*rule_index = (__u32)-1; /* No match initially */

	/* Bounded loop for BPF verifier compliance - only check first MAX_ACTIVE_RULES */
	for (i = 0; i < MAX_ACTIVE_RULES; i++) {
		__u32 key = i;
		struct rule_entry *rule = bpf_map_lookup_elem(&rules_map, &key);
		
		if (!rule || !rule->valid) {
			continue;
		}

		if (rule_matches(rule, packet_ip, protocol, src_port, dst_port, packet_direction)) {
			action = rule->action;
			*rule_index = i;
			break; /* First match wins */
		}
	}

	return action;
}

/*
 * Find matching IPv6 rule for packet
 * Returns action (ACTION_ALLOW or ACTION_DROP)
 * First matching rule wins
 * Updates rule_index with the matched rule index (or -1 if no match)
 */
static __always_inline __u8 find_matching_rule_v6(
	__u32 packet_ip[4],
	__u8 protocol,
	__u16 src_port,
	__u16 dst_port,
	__u8 packet_direction,
	__u32 *rule_index
) {
	__u8 action = ACTION_ALLOW; /* Default: allow */
	__u32 i;
	*rule_index = (__u32)-1; /* No match initially */

	/* Bounded loop for BPF verifier compliance - only check first MAX_ACTIVE_RULES */
	for (i = 0; i < MAX_ACTIVE_RULES; i++) {
		__u32 key = i;
		struct rule_entry_v6 *rule = bpf_map_lookup_elem(&rules_v6_map, &key);
		
		if (!rule || !rule->valid) {
			continue;
		}

		if (rule_matches_v6(rule, packet_ip, protocol, src_port, dst_port, packet_direction)) {
			action = rule->action;
			*rule_index = i;
			break; /* First match wins */
		}
	}

	return action;
}

#endif /* __FIREBEE_HELPERS_H__ */

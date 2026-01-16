/*
 * Firebee TC-BPF Egress Firewall - BPF Program
 * 
 * High-performance egress packet filtering using TC-BPF
 * Supports CIDR notation, protocol filtering, and port matching for outgoing traffic
 */

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "firebee_common.h"
#include "firebee_helpers.h"

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD

/* Maps are now defined in firebee_common.h and shared with XDP program */

/* ========================================================================
 * Packet Parsing Helpers (reuse from firebee_helpers.h)
 * ======================================================================== */

/*
 * Extract transport layer ports from packet
 * Only applies to TCP and UDP protocols
 */
static __always_inline void extract_ports_egress(
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
static __always_inline void extract_ports_egress_v6(
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
static __always_inline void log_packet_egress(__u32 dst_ip, __u8 action) {
	struct log_event *event = bpf_ringbuf_reserve(&log_events, sizeof(*event), 0);
	if (event) {
		event->src_ip = dst_ip;  // For egress, log destination IP
		event->action = action;
		bpf_ringbuf_submit(event, 0);
	}
}

/* ========================================================================
 * Rule Matching Engine
 * ======================================================================== */

/*
 * Check if packet matches a specific rule (egress version)
 * For egress traffic, we check the destination IP
 */
static __always_inline int rule_matches_egress(
	struct rule_entry *rule,
	__u32 packet_ip,
	__u8 protocol,
	__u16 src_port,
	__u16 dst_port,
	__u8 packet_direction
) {
	/* Check direction - DIRECTION_BOTH matches all traffic */
	if (rule->direction != DIRECTION_BOTH && rule->direction != packet_direction) {
		return 0;
	}

	/* Check IP with CIDR support (for egress, match destination IP) */
	if (!ip_matches(packet_ip, rule->src_ip, rule->subnet_mask)) {
		return 0;
	}

	/* Check protocol */
	if (!protocol_matches(protocol, rule->protocol)) {
		return 0;
	}

	/* Check ports (only for TCP/UDP) */
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
 * Find matching rule for egress packet and update statistics
 * Returns action (ACTION_ALLOW or ACTION_DROP)
 * First matching rule wins
 */
static __always_inline __u8 find_matching_rule_egress(
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
		
		bpf_printk("TC egress: loop iteration %d, rule ptr: %p", i, rule);
		
		if (!rule) {
			continue;
		}
		
		bpf_printk("TC egress: checking rule %d: ip=%u, dir=%d, valid=%d", i, rule->src_ip, rule->direction, rule->valid);
		
		if (!rule->valid) {
			continue;
		}

		if (rule_matches_egress(rule, packet_ip, protocol, src_port, dst_port, packet_direction)) {
			action = rule->action;
			*rule_index = i;
			bpf_printk("TC egress: MATCHED rule %d", i);
			break; /* First match wins */
		}
	}

	return action;
}

/*
 * Check if IPv6 packet matches a specific rule (egress version)
 * For egress traffic, we check the destination IP
 */
static __always_inline int rule_matches_egress_v6(
	struct rule_entry_v6 *rule,
	__u32 packet_ip[4],
	__u8 protocol,
	__u16 src_port,
	__u16 dst_port,
	__u8 packet_direction
) {
	/* Check direction - DIRECTION_BOTH matches all traffic */
	if (rule->direction != DIRECTION_BOTH && rule->direction != packet_direction) {
		return 0;
	}

	/* Check IPv6 address with prefix length */
	if (!ipv6_matches(packet_ip, rule->src_ip, rule->prefix_len)) {
		return 0;
	}

	/* Check protocol */
	if (!protocol_matches(protocol, rule->protocol)) {
		return 0;
	}

	/* Check ports (only for TCP/UDP) */
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
 * Find matching IPv6 rule for egress packet and update statistics
 * Returns action (ACTION_ALLOW or ACTION_DROP)
 * First matching rule wins
 */
static __always_inline __u8 find_matching_rule_egress_v6(
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

		if (rule_matches_egress_v6(rule, packet_ip, protocol, src_port, dst_port, packet_direction)) {
			action = rule->action;
			*rule_index = i;
			bpf_printk("TC egress v6: MATCHED rule %d", i);
			break; /* First match wins */
		}
	}

	return action;
}

/* ========================================================================
 * TC-BPF Egress Main Program
 * ======================================================================== */

SEC("tc")
int tc_egress_firewall(struct __sk_buff *skb) {
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	
	/* Parse Ethernet header */
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		return TC_ACT_OK;
	}

	__u16 eth_proto = bpf_ntohs(eth->h_proto);

	/* Handle IPv4 packets */
	if (eth_proto == ETH_P_IP) {
		/* Parse IP header */
		struct iphdr *iph = (void *)(eth + 1);
		if ((void *)(iph + 1) > data_end) {
			return TC_ACT_OK;
		}

		/* Extract packet information - for egress, check destination IP */
		__u32 packet_ip = bpf_ntohl(iph->daddr);
		__u8 protocol = iph->protocol;
		__u16 src_port, dst_port;
		__u32 matched_rule_idx;
		__u8 packet_direction = DIRECTION_EGRESS;
		
		bpf_printk("TC egress: packet to %pI4, proto %d", &iph->daddr, protocol);
		
		extract_ports_egress(iph, data_end, protocol, &src_port, &dst_port);

		/* Find matching firewall rule */
		__u8 action = find_matching_rule_egress(packet_ip, protocol, src_port, dst_port, packet_direction, &matched_rule_idx);

		bpf_printk("TC egress: matched rule idx %d, action %d", matched_rule_idx, action);

		/* Update statistics if a rule matched */
		if (matched_rule_idx != (__u32)-1) {
			struct rule_stats *stats = bpf_map_lookup_elem(&rule_stats_map, &matched_rule_idx);
			if (stats) {
				__u64 packet_size = (__u64)(data_end - data);
				__sync_fetch_and_add(&stats->packets, 1);
				__sync_fetch_and_add(&stats->bytes, packet_size);
			}
		}

		/* Log the event */
		log_packet_egress(packet_ip, action);

		/* Apply action */
		if (action == ACTION_DROP) {
			bpf_printk("TC egress: DROPPING packet");
			return TC_ACT_SHOT;
		}
		return TC_ACT_OK;
	}
	/* Handle IPv6 packets */
	else if (eth_proto == ETH_P_IPV6) {
		/* Parse IPv6 header */
		struct ipv6hdr *ip6h = (void *)(eth + 1);
		if ((void *)(ip6h + 1) > data_end) {
			return TC_ACT_OK;
		}

		/* Extract IPv6 destination address (for egress filtering) */
		__u32 packet_ip[4];
		packet_ip[0] = ip6h->daddr.in6_u.u6_addr32[0];
		packet_ip[1] = ip6h->daddr.in6_u.u6_addr32[1];
		packet_ip[2] = ip6h->daddr.in6_u.u6_addr32[2];
		packet_ip[3] = ip6h->daddr.in6_u.u6_addr32[3];

		/* Extract protocol from next header */
		__u8 protocol = ip6h->nexthdr;
		__u16 src_port, dst_port;
		__u32 matched_rule_idx;
		__u8 packet_direction = DIRECTION_EGRESS;
		
		extract_ports_egress_v6(ip6h, data_end, protocol, &src_port, &dst_port);

		/* Find matching IPv6 firewall rule */
		__u8 action = find_matching_rule_egress_v6(packet_ip, protocol, src_port, dst_port, packet_direction, &matched_rule_idx);

		bpf_printk("TC egress v6: matched rule idx %d, action %d", matched_rule_idx, action);

		/* Update IPv6 statistics if a rule matched */
		if (matched_rule_idx != (__u32)-1) {
			struct rule_stats *stats = bpf_map_lookup_elem(&rule_stats_v6_map, &matched_rule_idx);
			if (stats) {
				__u64 packet_size = (__u64)(data_end - data);
				__sync_fetch_and_add(&stats->packets, 1);
				__sync_fetch_and_add(&stats->bytes, packet_size);
			}
		}

		/* Log the event (using first 32-bit word for compatibility) */
		log_packet_egress(bpf_ntohl(packet_ip[0]), action);

		/* Apply action */
		if (action == ACTION_DROP) {
			bpf_printk("TC egress v6: DROPPING packet");
			return TC_ACT_SHOT;
		}
		return TC_ACT_OK;
	}

	/* Pass all other protocols */
	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";

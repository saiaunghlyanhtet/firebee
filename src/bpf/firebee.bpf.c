/*
 * Firebee XDP Firewall - BPF Program
 */

#include <linux/bpf.h>
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

/*
 * Extract transport layer ports from packet
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
static __always_inline void log_packet(__u32 src_ip, __u8 action) {
	struct log_event *event = bpf_ringbuf_reserve(&log_events, sizeof(*event), 0);
	if (event) {
		event->src_ip = src_ip;
		event->action = action;
		bpf_ringbuf_submit(event, 0);
	}
}


/*
 * Check if packet matches a specific rule
 * Returns 1 if all conditions match, 0 otherwise
 * 
 * Note: XDP programs only see ingress traffic by default.
 * Direction filtering is implemented for future TC-BPF egress support.
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
	#pragma unroll
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
 * Find matching IPv6 rule for packet and update statistics
 * Returns action (ACTION_ALLOW or ACTION_DROP)
 * First matching rule wins
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
	#pragma unroll
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

/* ========================================================================
 * XDP Main Program
 * ======================================================================== */

SEC("xdp")
int xdp_firewall(struct xdp_md *ctx) {
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		return XDP_PASS;
	}

	__u16 eth_proto = bpf_ntohs(eth->h_proto);

	if (eth_proto == ETH_P_IP) {
		struct iphdr *iph = (void *)(eth + 1);
		if ((void *)(iph + 1) > data_end) {
			return XDP_PASS;
		}

		__u32 packet_ip = bpf_ntohl(iph->saddr);
		__u8 protocol = iph->protocol;
		__u16 src_port, dst_port;
		__u32 matched_rule_idx;
		__u8 packet_direction = DIRECTION_INGRESS;
		
		extract_ports(iph, data_end, protocol, &src_port, &dst_port);

		__u8 action = find_matching_rule(packet_ip, protocol, src_port, dst_port, packet_direction, &matched_rule_idx);

		if (matched_rule_idx != (__u32)-1) {
			struct rule_stats *stats = bpf_map_lookup_elem(&rule_stats_map, &matched_rule_idx);
			if (stats) {
				__u64 packet_size = (__u64)(data_end - data);
				__sync_fetch_and_add(&stats->packets, 1);
				__sync_fetch_and_add(&stats->bytes, packet_size);
			}
		}

		log_packet(packet_ip, action);

		return (action == ACTION_DROP) ? XDP_DROP : XDP_PASS;
	}
	else if (eth_proto == ETH_P_IPV6) {
		struct ipv6hdr *ip6h = (void *)(eth + 1);
		if ((void *)(ip6h + 1) > data_end) {
			return XDP_PASS;
		}

		__u32 packet_ip[4];
		packet_ip[0] = ip6h->saddr.in6_u.u6_addr32[0];
		packet_ip[1] = ip6h->saddr.in6_u.u6_addr32[1];
		packet_ip[2] = ip6h->saddr.in6_u.u6_addr32[2];
		packet_ip[3] = ip6h->saddr.in6_u.u6_addr32[3];

		__u8 protocol = ip6h->nexthdr;
		__u16 src_port, dst_port;
		__u32 matched_rule_idx;
		__u8 packet_direction = DIRECTION_INGRESS;
		
		extract_ports_v6(ip6h, data_end, protocol, &src_port, &dst_port);

		__u8 action = find_matching_rule_v6(packet_ip, protocol, src_port, dst_port, packet_direction, &matched_rule_idx);

		if (matched_rule_idx != (__u32)-1) {
			struct rule_stats *stats = bpf_map_lookup_elem(&rule_stats_v6_map, &matched_rule_idx);
			if (stats) {
				__u64 packet_size = (__u64)(data_end - data);
				__sync_fetch_and_add(&stats->packets, 1);
				__sync_fetch_and_add(&stats->bytes, packet_size);
			}
		}

		log_packet(bpf_ntohl(packet_ip[0]), action);

		return (action == ACTION_DROP) ? XDP_DROP : XDP_PASS;
	}

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

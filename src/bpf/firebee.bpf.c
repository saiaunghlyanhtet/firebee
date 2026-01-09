/*
 * Firebee XDP Firewall - BPF Program
 * 
 * High-performance packet filtering using eBPF/XDP
 * Supports CIDR notation, protocol filtering, and port matching
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "firebee_common.h"
#include "firebee_helpers.h"

#define ETH_P_IP 0x0800
#define MAX_RULES 1024

/* ========================================================================
 * BPF Maps - Data structures shared between kernel and userspace
 * ======================================================================== */

/*
 * Primary rules storage - Array map for efficient iteration
 * Allows linear scan for CIDR matching and wildcard rules
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct rule_entry);
	__uint(max_entries, MAX_RULES);
} rules_map SEC(".maps");

/*
 * Rule index - Hash map for quick lookups by userspace
 * Maps rule key to array index for O(1) updates/deletes
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct rule_key);
	__type(value, __u32);
	__uint(max_entries, MAX_RULES);
} rules_index SEC(".maps");

/*
 * Rule metadata - Hash map indexed by rule name
 * Stores human-readable information (name, description)
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, char[64]);
	__type(value, struct rule_metadata);
	__uint(max_entries, MAX_RULES);
} rule_metadata_map SEC(".maps");

/*
 * Event logging - Ring buffer for userspace event consumption
 * Used to send packet events to TUI for display
 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24); /* 16MB */
} log_events SEC(".maps");

/* ========================================================================
 * Packet Parsing Helpers
 * ======================================================================== */

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

/* ========================================================================
 * Rule Matching Engine
 * ======================================================================== */

/*
 * Check if packet matches a specific rule
 * Returns 1 if all conditions match, 0 otherwise
 */
static __always_inline int rule_matches(
	struct rule_entry *rule,
	__u32 packet_ip,
	__u8 protocol,
	__u16 src_port,
	__u16 dst_port
) {
	/* Check IP with CIDR support */
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
 * Find matching rule for packet
 * Returns action (ACTION_ALLOW or ACTION_DROP)
 * First matching rule wins
 */
static __always_inline __u8 find_matching_rule(
	__u32 packet_ip,
	__u8 protocol,
	__u16 src_port,
	__u16 dst_port
) {
	__u8 action = ACTION_ALLOW; /* Default: allow */
	__u32 i;

	/* Bounded loop for BPF verifier compliance */
	#pragma unroll
	for (i = 0; i < MAX_RULES; i++) {
		__u32 key = i;
		struct rule_entry *rule = bpf_map_lookup_elem(&rules_map, &key);
		
		if (!rule || !rule->valid) {
			continue;
		}

		if (rule_matches(rule, packet_ip, protocol, src_port, dst_port)) {
			action = rule->action;
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
	
	/* Parse Ethernet header */
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		return XDP_PASS;
	}

	/* Only process IPv4 packets */
	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		return XDP_PASS;
	}
	
	/* Parse IP header */
	struct iphdr *iph = (void *)(eth + 1);
	if ((void *)(iph + 1) > data_end) {
		return XDP_PASS;
	}

	/* Extract packet information */
	__u32 packet_ip = bpf_ntohl(iph->saddr);
	__u8 protocol = iph->protocol;
	__u16 src_port, dst_port;
	
	extract_ports(iph, data_end, protocol, &src_port, &dst_port);

	/* Find matching firewall rule */
	__u8 action = find_matching_rule(packet_ip, protocol, src_port, dst_port);

	/* Log the event */
	log_packet(packet_ip, action);

	/* Apply action */
	return (action == ACTION_DROP) ? XDP_DROP : XDP_PASS;
}

char _license[] SEC("license") = "GPL";

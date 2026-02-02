/*
 * Firebee TC-BPF Egress Firewall - BPF Program
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

/* ========================================================================
 * TC-BPF Egress Main Program
 * ======================================================================== */

SEC("tc")
int tc_egress_firewall(struct __sk_buff *skb) {
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		return TC_ACT_OK;
	}

	__u16 eth_proto = bpf_ntohs(eth->h_proto);

	if (eth_proto == ETH_P_IP) {
		struct iphdr *iph = (void *)(eth + 1);
		if ((void *)(iph + 1) > data_end) {
			return TC_ACT_OK;
		}

		__u32 packet_ip = bpf_ntohl(iph->daddr);
		__u8 protocol = iph->protocol;
		__u16 src_port, dst_port;
		__u32 matched_rule_idx;
		__u8 packet_direction = DIRECTION_EGRESS;
		
		bpf_printk("TC egress: packet to %pI4, proto %d", &iph->daddr, protocol);
		
		extract_ports(iph, data_end, protocol, &src_port, &dst_port);

		__u8 action = find_matching_rule(packet_ip, protocol, src_port, dst_port, packet_direction, &matched_rule_idx);

		bpf_printk("TC egress: matched rule idx %d, action %d", matched_rule_idx, action);

		if (matched_rule_idx != (__u32)-1) {
			struct rule_stats *stats = bpf_map_lookup_elem(&rule_stats_map, &matched_rule_idx);
			if (stats) {
				__u64 packet_size = (__u64)(data_end - data);
				__sync_fetch_and_add(&stats->packets, 1);
				__sync_fetch_and_add(&stats->bytes, packet_size);
			}
		}

		log_packet(packet_ip, action);

		if (action == ACTION_DROP) {
			bpf_printk("TC egress: DROPPING packet");
			return TC_ACT_SHOT;
		}
		return TC_ACT_OK;
	}
	else if (eth_proto == ETH_P_IPV6) {
		struct ipv6hdr *ip6h = (void *)(eth + 1);
		if ((void *)(ip6h + 1) > data_end) {
			return TC_ACT_OK;
		}

		__u32 packet_ip[4];
		packet_ip[0] = ip6h->daddr.in6_u.u6_addr32[0];
		packet_ip[1] = ip6h->daddr.in6_u.u6_addr32[1];
		packet_ip[2] = ip6h->daddr.in6_u.u6_addr32[2];
		packet_ip[3] = ip6h->daddr.in6_u.u6_addr32[3];

		__u8 protocol = ip6h->nexthdr;
		__u16 src_port, dst_port;
		__u32 matched_rule_idx;
		__u8 packet_direction = DIRECTION_EGRESS;
		
		extract_ports_v6(ip6h, data_end, protocol, &src_port, &dst_port);

		__u8 action = find_matching_rule_v6(packet_ip, protocol, src_port, dst_port, packet_direction, &matched_rule_idx);

		bpf_printk("TC egress v6: matched rule idx %d, action %d", matched_rule_idx, action);

		if (matched_rule_idx != (__u32)-1) {
			struct rule_stats *stats = bpf_map_lookup_elem(&rule_stats_v6_map, &matched_rule_idx);
			if (stats) {
				__u64 packet_size = (__u64)(data_end - data);
				__sync_fetch_and_add(&stats->packets, 1);
				__sync_fetch_and_add(&stats->bytes, packet_size);
			}
		}

		log_packet(bpf_ntohl(packet_ip[0]), action);

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

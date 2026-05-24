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
		__u32 local_ip  = bpf_ntohl(iph->daddr);
		__u8 protocol = iph->protocol;
		__u16 src_port, dst_port;
		__u32 matched_rule_idx;
		__u8 packet_direction = DIRECTION_INGRESS;

		extract_ports(iph, data_end, protocol, &src_port, &dst_port);

		/* Capture DNS responses (UDP source port 53) for FQDN resolution */
		if (protocol == IPPROTO_UDP && src_port == 53) {
			struct udphdr *udph = (void *)iph + (iph->ihl * 4);
			if ((void *)(udph + 1) <= data_end) {
				void *dns_payload = (void *)(udph + 1);
				capture_dns_response(dns_payload, data_end, iph->saddr);
			}
		}

		/* ---------------------------------------------------------------
		 * Conntrack fast path: allow return traffic for tracked connections
		 * without evaluating the full rule list.
		 *
		 * Reverse lookup: finds entries created by the egress path
		 * (key stored as local→remote; ingress packet is remote→local).
		 * Forward lookup: finds entries created when we accepted an inbound
		 * connection (key stored as remote→local; subsequent packets match).
		 * --------------------------------------------------------------- */
		if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
			struct conntrack_entry *ct;

			ct = ct_lookup(local_ip, packet_ip, dst_port, src_port, protocol);
			if (!ct)
				ct = ct_lookup(packet_ip, local_ip, src_port, dst_port, protocol);

			if (ct) {
				__u64 now = bpf_ktime_get_ns();
				__u64 timeout_ns = (__u64)ct->timeout_sec * 1000000000ULL;

				if (now - ct->last_seen < timeout_ns) {
					if (protocol == IPPROTO_TCP) {
						struct tcphdr *tcph = (void *)iph + (iph->ihl * 4);
						if ((void *)(tcph + 1) <= data_end) {
							if (tcph->rst) {
								ct->state = CT_CLOSED;
							} else if (tcph->fin) {
								ct->state       = CT_FIN_WAIT;
								ct->timeout_sec = CT_TIMEOUT_FIN;
								ct->last_seen   = now;
							} else if (tcph->syn && tcph->ack &&
								   ct->state == CT_SYN_SENT) {
								ct->state       = CT_ESTABLISHED;
								ct->timeout_sec = CT_TIMEOUT_ESTABLISHED;
								ct->last_seen   = now;
							} else if (ct->state != CT_CLOSED) {
								ct->last_seen = now;
							}
						}
					} else {
						ct->last_seen = now;
					}

					if (ct->state != CT_CLOSED) {
						log_packet(packet_ip, ACTION_ALLOW);
						return XDP_PASS;
					}
				}
			}
		}

		__u8 action = find_matching_rule(packet_ip, protocol, src_port, dst_port, packet_direction, &matched_rule_idx);

		if (matched_rule_idx != (__u32)-1) {
			struct rule_stats *stats = bpf_map_lookup_elem(&rule_stats_map, &matched_rule_idx);
			if (stats) {
				__u64 packet_size = (__u64)(data_end - data);
				__sync_fetch_and_add(&stats->packets, 1);
				__sync_fetch_and_add(&stats->bytes, packet_size);
			}
		}

		/* Track newly allowed TCP/UDP connections so return traffic is
		 * fast-pathed by the conntrack check above. */
		if (action == ACTION_ALLOW &&
		    (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP)) {
			__u8  ct_state   = CT_ESTABLISHED;
			__u32 ct_timeout = CT_TIMEOUT_ESTABLISHED;
			if (protocol == IPPROTO_TCP) {
				struct tcphdr *tcph = (void *)iph + (iph->ihl * 4);
				if ((void *)(tcph + 1) <= data_end &&
				    tcph->syn && !tcph->ack) {
					ct_state   = CT_SYN_SENT;
					ct_timeout = CT_TIMEOUT_SYN;
				}
			}
			ct_upsert(packet_ip, local_ip, src_port, dst_port,
				  protocol, ct_state, ct_timeout);
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

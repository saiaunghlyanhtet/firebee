#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_ICMP 1
#define IPPROTO_ANY 255
#define PORT_ANY 0
#define ETH_P_IP 0x0800

// Rule entry structure combining key and value
struct rule_entry {
    __u32 src_ip;
    __u32 subnet_mask;  // For CIDR matching
    __u8 protocol;      // IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP, or IPPROTO_ANY
    __u8 action;        // 1 = allow, 0 = drop
    __u16 src_port;     // Source port (0 = any)
    __u16 dst_port;     // Destination port (0 = any)
    __u8 valid;         // 1 = entry is valid, 0 = empty slot
    __u8 _padding[3];   // Padding for alignment
};

// Key structure for metadata map (kept for backward compatibility)
struct rule_key {
    __u32 src_ip;
    __u32 subnet_mask;
    __u8 protocol;
    __u16 src_port;
    __u16 dst_port;
};

// Rule metadata structure
struct rule_metadata {
    __u32 ip;
    __u32 subnet_mask;
    __u8 action;
    __u8 protocol;
    __u16 src_port;
    __u16 dst_port;
    char name[64];
    char description[128];
};

// Array map to hold firewall rules for iteration and CIDR matching
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct rule_entry);
	__uint(max_entries, 1024);
} rules_map SEC(".maps");

// Hash map for backward compatibility and quick rule management
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct rule_key);
	__type(value, __u32); // Index in rules_map array
	__uint(max_entries, 1024);
} rules_index SEC(".maps");

// Map to hold rule metadata (indexed by rule name)
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, char[64]); // rule name
	__type(value, struct rule_metadata);
	__uint(max_entries, 1024);
} rule_metadata_map SEC(".maps");

// Map for logging (ring buffer)
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24); // 16MB
} log_events SEC(".maps");

// Log event structure
struct log_event {
	__u32 src_ip;
	__u32 action; // 1 = allow, 0 = deny
};

static __always_inline int ip_matches(__u32 packet_ip, __u32 rule_ip, __u32 subnet_mask) {
    if (subnet_mask == 0xFFFFFFFF) {
        // Exact match
        return packet_ip == rule_ip;
    } else if (subnet_mask == 0) {
        // Match any IP
        return 1;
    } else {
        // CIDR match
        return (packet_ip & subnet_mask) == (rule_ip & subnet_mask);
    }
}

static __always_inline int port_matches(__u16 packet_port, __u16 rule_port) {
    return rule_port == PORT_ANY || packet_port == rule_port;
}

SEC("xdp")
int xdp_firewall(struct xdp_md *ctx) {
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		return XDP_PASS;
	}

	// Only process IP packets
	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		return XDP_PASS;
	}
	
	struct iphdr *iph = (void *)(eth + 1);
	if ((void *)(iph + 1) > data_end) {
		return XDP_PASS;
	}

	__u8 protocol = iph->protocol;
	__u16 src_port = 0;
	__u16 dst_port = 0;

	if (protocol == IPPROTO_TCP) {
		struct tcphdr *tcph = (void *)iph + (iph->ihl * 4);
		if ((void *)(tcph + 1) > data_end) {
			return XDP_PASS;
		}
		src_port = bpf_ntohs(tcph->source);
		dst_port = bpf_ntohs(tcph->dest);
	} else if (protocol == IPPROTO_UDP) {
		struct udphdr *udph = (void *)iph + (iph->ihl * 4);
		if ((void *)(udph + 1) > data_end) {
			return XDP_PASS;
		}
		src_port = bpf_ntohs(udph->source);
		dst_port = bpf_ntohs(udph->dest);
	}

	__u32 packet_ip = bpf_ntohl(iph->saddr);
	__u8 default_action = 1; // Default: allow
	__u8 matched_action = default_action;

	// Iterate through rules array to find a match
	// This allows proper CIDR and wildcard matching
	// Use bounded loop for BPF verifier compliance
	__u32 i;
	for (i = 0; i < 1024; i++) {
		__u32 key = i;
		struct rule_entry *rule = bpf_map_lookup_elem(&rules_map, &key);
		
		if (!rule || !rule->valid) {
			continue;
		}

		// Check if IP matches (with CIDR support)
		if (!ip_matches(packet_ip, rule->src_ip, rule->subnet_mask)) {
			continue;
		}

		// Check if protocol matches
		if (rule->protocol != IPPROTO_ANY && rule->protocol != protocol) {
			continue;
		}

		// Check if ports match (only for TCP/UDP)
		if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
			if (!port_matches(src_port, rule->src_port)) {
				continue;
			}
			if (!port_matches(dst_port, rule->dst_port)) {
				continue;
			}
		}

		// All conditions matched - apply this rule
		matched_action = rule->action;
		break; // First match wins
	}

	struct log_event *event = bpf_ringbuf_reserve(&log_events, sizeof(*event), 0);
	if (event) {
		event->src_ip = packet_ip;
		event->action = matched_action;
		bpf_ringbuf_submit(event, 0);
	}

	if (matched_action == 0) {
		return XDP_DROP;
	}
	
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>


// Key structure for the rules map
struct rule_key {
    __u32 src_ip;
};

// Map to hold the firewall rules
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct rule_key);
	__type(value, __u8); // 1 = allow, 0 = deny
	__uint(max_entries, 1024);
} rules_map SEC(".maps");

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

SEC("xdp")
int xdp_firewall(struct xdp_md *ctx) {
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	
	struct iphdr *iph = data + sizeof(struct ethhdr);
	if ((void *)iph + sizeof(*iph) > data_end) {
		return XDP_PASS;
	}

	struct rule_key key = { .src_ip = iph->saddr };
	__u8 *action = bpf_map_lookup_elem(&rules_map, &key);


	struct log_event *event = bpf_ringbuf_reserve(&log_events, sizeof(*event), 0);
	if (!event) {
		return XDP_PASS;
	}

	event->src_ip = iph->saddr;
	if (action && *action == 0) {
		event->action = 0;
		bpf_ringbuf_submit(event, 0);
		return XDP_DROP;
	}
	
	event->action = 1;
	bpf_ringbuf_submit(event, 0);
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

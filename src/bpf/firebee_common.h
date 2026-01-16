#ifndef __FIREBEE_COMMON_H__
#define __FIREBEE_COMMON_H__

#include <linux/types.h>

/* Protocol definitions */
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_ICMP 1
#define IPPROTO_ICMPV6 58
#define IPPROTO_ANY 255

/* Port wildcard */
#define PORT_ANY 0

/* Actions */
#define ACTION_DROP 0
#define ACTION_ALLOW 1

/* Direction */
#define DIRECTION_INGRESS 0  /* Incoming traffic (default for XDP) */
#define DIRECTION_EGRESS 1   /* Outgoing traffic (requires TC-BPF) */
#define DIRECTION_BOTH 2     /* Both directions */

/* 
 * Rule entry structure for the BPF array map
 * Combines key and value for efficient iteration and CIDR matching
 */
struct rule_entry {
    __u32 src_ip;         /* Source IP address in network byte order */
    __u32 subnet_mask;    /* Subnet mask for CIDR matching (0 = any, 0xFFFFFFFF = exact) */
    __u8 protocol;        /* IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP, or IPPROTO_ANY */
    __u8 action;          /* ACTION_ALLOW or ACTION_DROP */
    __u8 direction;       /* DIRECTION_INGRESS, DIRECTION_EGRESS, or DIRECTION_BOTH */
    __u8 valid;           /* 1 = entry is valid, 0 = empty slot */
    __u16 src_port;       /* Source port (PORT_ANY for wildcard) */
    __u16 dst_port;       /* Destination port (PORT_ANY for wildcard) */
    __u8 _padding[2];     /* Padding for alignment */
};

/* 
 * Rule key structure for hash-based lookups
 * Used for quick rule management via userspace
 */
struct rule_key {
    __u32 src_ip;
    __u32 subnet_mask;
    __u8 protocol;
    __u16 src_port;
    __u16 dst_port;
};

/* 
 * Rule metadata structure
 * Stores human-readable information about rules
 */
struct rule_metadata {
    __u32 ip;
    __u32 subnet_mask;
    __u8 action;
    __u8 protocol;
    __u8 direction;
    __u8 _padding;
    __u16 src_port;
    __u16 dst_port;
    char name[64];
    char description[128];
};

/* 
 * Log event structure for ring buffer
 * Sent to userspace for each packet evaluation
 */
struct log_event {
    __u32 src_ip;    /* Source IP in host byte order */
    __u32 action;    /* ACTION_ALLOW or ACTION_DROP */
};

/* 
 * Rule statistics structure
 * Tracks packet and byte counts per rule
 */
struct rule_stats {
    __u64 packets;   /* Total packets matched */
    __u64 bytes;     /* Total bytes matched */
};

/* ========================================================================
 * IPv6 Support Structures
 * ======================================================================== */

/* 
 * IPv6 Rule entry structure for the BPF array map
 * Similar to rule_entry but with IPv6 addresses (128-bit)
 */
struct rule_entry_v6 {
    __u32 src_ip[4];      /* Source IPv6 address (network byte order, 128-bit) */
    __u8 prefix_len;      /* Prefix length for CIDR matching (0-128) */
    __u8 protocol;        /* IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMPV6, or IPPROTO_ANY */
    __u8 action;          /* ACTION_ALLOW or ACTION_DROP */
    __u8 direction;       /* DIRECTION_INGRESS, DIRECTION_EGRESS, or DIRECTION_BOTH */
    __u8 valid;           /* 1 = entry is valid, 0 = empty slot */
    __u8 _padding[3];     /* Padding for alignment */
    __u16 src_port;       /* Source port (PORT_ANY for wildcard) */
    __u16 dst_port;       /* Destination port (PORT_ANY for wildcard) */
};

/* 
 * IPv6 Rule metadata structure
 * Stores human-readable information about IPv6 rules
 */
struct rule_metadata_v6 {
    __u32 ip[4];
    __u8 prefix_len;
    __u8 action;
    __u8 protocol;
    __u8 direction;
    __u16 src_port;
    __u16 dst_port;
    char name[64];
    char description[128];
};

/* ========================================================================
 * Shared BPF Maps - Defined once and pinned for use across programs
 * These maps are shared between XDP and TC-BPF programs via pinning
 * ======================================================================== */

/* Maximum number of firewall rules (map storage capacity) */
#define MAX_RULES 1024

/* Maximum number of active rules to check per packet (loop bound for BPF verifier)
 * This must be small enough to keep the BPF program under 1M instruction limit.
 * The BPF verifier unrolls loops, so 128 rules × ~99 instructions ≈ 12.6K instructions
 * per loop, which leaves plenty of headroom under the 1M limit. */
#define MAX_ACTIVE_RULES 128

/*
 * Primary rules storage - Array map for efficient iteration
 * Shared between XDP (ingress) and TC (egress) programs
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct rule_entry);
	__uint(max_entries, MAX_RULES);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} rules_map SEC(".maps");

/*
 * Rule metadata - Hash map indexed by rule name
 * Stores human-readable information (name, description)
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, char[64]);
	__type(value, struct rule_metadata);
	__uint(max_entries, MAX_RULES);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} rule_metadata_map SEC(".maps");

/*
 * Event logging - Ring buffer for userspace event consumption
 * Shared logging for both ingress and egress events
 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24); /* 16MB */
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} log_events SEC(".maps");

/*
 * Rule statistics - Array map for per-rule packet/byte counters
 * Indexed by rule array index, parallel to rules_map
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct rule_stats);
	__uint(max_entries, MAX_RULES);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} rule_stats_map SEC(".maps");

/*
 * Rule index - Hash map for quick lookups by userspace (XDP only)
 * Maps rule key to array index for O(1) updates/deletes
 * NOT shared with TC program
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct rule_key);
	__type(value, __u32);
	__uint(max_entries, MAX_RULES);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} rules_index SEC(".maps");

/* ========================================================================
 * IPv6 BPF Maps - Shared between XDP and TC programs
 * ======================================================================== */

/*
 * Primary IPv6 rules storage - Array map for efficient iteration
 * Shared between XDP (ingress) and TC (egress) programs
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct rule_entry_v6);
	__uint(max_entries, MAX_RULES);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} rules_v6_map SEC(".maps");

/*
 * IPv6 Rule metadata - Hash map indexed by rule name
 * Stores human-readable information (name, description)
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, char[64]);
	__type(value, struct rule_metadata_v6);
	__uint(max_entries, MAX_RULES);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} rule_metadata_v6_map SEC(".maps");

/*
 * IPv6 Rule statistics - Array map for per-rule packet/byte counters
 * Indexed by rule array index, parallel to rules_v6_map
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct rule_stats);
	__uint(max_entries, MAX_RULES);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} rule_stats_v6_map SEC(".maps");

#endif /* __FIREBEE_COMMON_H__ */

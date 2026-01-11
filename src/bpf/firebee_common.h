#ifndef __FIREBEE_COMMON_H__
#define __FIREBEE_COMMON_H__

#include <linux/types.h>

/* Protocol definitions */
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_ICMP 1
#define IPPROTO_ANY 255

/* Port wildcard */
#define PORT_ANY 0

/* Actions */
#define ACTION_DROP 0
#define ACTION_ALLOW 1

/* 
 * Rule entry structure for the BPF array map
 * Combines key and value for efficient iteration and CIDR matching
 */
struct rule_entry {
    __u32 src_ip;         /* Source IP address in network byte order */
    __u32 subnet_mask;    /* Subnet mask for CIDR matching (0 = any, 0xFFFFFFFF = exact) */
    __u8 protocol;        /* IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP, or IPPROTO_ANY */
    __u8 action;          /* ACTION_ALLOW or ACTION_DROP */
    __u16 src_port;       /* Source port (PORT_ANY for wildcard) */
    __u16 dst_port;       /* Destination port (PORT_ANY for wildcard) */
    __u8 valid;           /* 1 = entry is valid, 0 = empty slot */
    __u8 _padding[3];     /* Padding for alignment to 20 bytes */
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

#endif /* __FIREBEE_COMMON_H__ */

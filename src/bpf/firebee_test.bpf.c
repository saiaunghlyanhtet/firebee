/* Firebee BPF Helper Function Tests */

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
#include "test_common.h"

char __license[] SEC("license") = "GPL";

/* IPv4 Matching Tests */
CHECK("ip_matches")
int test_ip_matches(struct xdp_md *ctx)
{
	test_init();

	TEST("exact_match", {
		__u32 packet_ip = 0xC0A80101; /* 192.168.1.1 */
		__u32 rule_ip = 0xC0A80101;
		__u32 subnet_mask = 0xFFFFFFFF; /* /32 */
		
		int result = ip_matches(packet_ip, rule_ip, subnet_mask);
		if (!result)
			test_fatal("Expected exact IP match for 192.168.1.1/32");
	});

	TEST("exact_mismatch", {
		__u32 packet_ip = 0xC0A80101; /* 192.168.1.1 */
		__u32 rule_ip = 0xC0A80102;   /* 192.168.1.2 */
		__u32 subnet_mask = 0xFFFFFFFF;
		
		int result = ip_matches(packet_ip, rule_ip, subnet_mask);
		if (result)
			test_fatal("Expected IP mismatch for different IPs");
	});

	TEST("cidr_24_match", {
		__u32 packet_ip = 0xC0A80101; /* 192.168.1.1 */
		__u32 rule_ip = 0xC0A80100;   /* 192.168.1.0 */
		__u32 subnet_mask = 0xFFFFFF00; /* /24 */
		
		int result = ip_matches(packet_ip, rule_ip, subnet_mask);
		if (!result)
			test_fatal("Expected /24 CIDR match");
	});

	TEST("cidr_24_mismatch", {
		__u32 packet_ip = 0xC0A80201; /* 192.168.2.1 */
		__u32 rule_ip = 0xC0A80100;   /* 192.168.1.0 */
		__u32 subnet_mask = 0xFFFFFF00; /* /24 */
		
		int result = ip_matches(packet_ip, rule_ip, subnet_mask);
		if (result)
			test_fatal("Expected /24 CIDR mismatch for different subnets");
	});

	TEST("cidr_16_match", {
		__u32 packet_ip = 0xC0A80101; /* 192.168.1.1 */
		__u32 rule_ip = 0xC0A80000;   /* 192.168.0.0 */
		__u32 subnet_mask = 0xFFFF0000; /* /16 */
		
		int result = ip_matches(packet_ip, rule_ip, subnet_mask);
		if (!result)
			test_fatal("Expected /16 CIDR match");
	});

	TEST("any_ip_match", {
		__u32 packet_ip = 0xC0A80101; /* 192.168.1.1 */
		__u32 rule_ip = 0x00000000;   /* 0.0.0.0 */
		__u32 subnet_mask = 0x00000000; /* /0 - any */
		
		int result = ip_matches(packet_ip, rule_ip, subnet_mask);
		if (!result)
			test_fatal("Expected any IP (0.0.0.0/0) to match");
	});

	test_finish();
}

/* Port Matching Tests */
CHECK("port_matches")
int test_port_matches(struct xdp_md *ctx)
{
	test_init();

	TEST("exact_match", {
		__u16 packet_port = 80;
		__u16 rule_port = 80;
		
		int result = port_matches(packet_port, rule_port);
		if (!result)
			test_fatal("Expected exact port match for port 80");
	});

	TEST("exact_mismatch", {
		__u16 packet_port = 80;
		__u16 rule_port = 443;
		
		int result = port_matches(packet_port, rule_port);
		if (result)
			test_fatal("Expected port mismatch for 80 vs 443");
	});

	TEST("any_port_match", {
		__u16 packet_port = 12345;
		__u16 rule_port = PORT_ANY;
		
		int result = port_matches(packet_port, rule_port);
		if (!result)
			test_fatal("Expected PORT_ANY (0) to match any port");
	});

	test_finish();
}

/* Protocol Matching Tests */
CHECK("protocol_matches")
int test_protocol_matches(struct xdp_md *ctx)
{
	test_init();

	TEST("tcp_match", {
		__u8 packet_proto = IPPROTO_TCP;
		__u8 rule_proto = IPPROTO_TCP;
		
		int result = protocol_matches(packet_proto, rule_proto);
		if (!result)
			test_fatal("Expected TCP protocol match");
	});

	TEST("tcp_udp_mismatch", {
		__u8 packet_proto = IPPROTO_TCP;
		__u8 rule_proto = IPPROTO_UDP;
		
		int result = protocol_matches(packet_proto, rule_proto);
		if (result)
			test_fatal("Expected TCP/UDP protocol mismatch");
	});

	TEST("any_protocol_match", {
		__u8 packet_proto = IPPROTO_ICMP;
		__u8 rule_proto = IPPROTO_ANY;
		
		int result = protocol_matches(packet_proto, rule_proto);
		if (!result)
			test_fatal("Expected IPPROTO_ANY to match ICMP");
	});

	test_finish();
}

/* IPv6 Matching Tests */
CHECK("ipv6_matches")
int test_ipv6_matches(struct xdp_md *ctx)
{
	test_init();

	TEST("exact_match", {
		/* 2001:db8::1 */
		__u32 packet_ip[4];
		__u32 rule_ip[4];
		packet_ip[0] = bpf_htonl(0x20010db8);
		packet_ip[1] = 0;
		packet_ip[2] = 0;
		packet_ip[3] = bpf_htonl(0x1);
		rule_ip[0] = bpf_htonl(0x20010db8);
		rule_ip[1] = 0;
		rule_ip[2] = 0;
		rule_ip[3] = bpf_htonl(0x1);
		__u8 prefix_len = 128; /* /128 - exact match */
		
		int result = ipv6_matches(packet_ip, rule_ip, prefix_len);
		if (!result)
			test_fatal("Expected exact IPv6 match for 2001:db8::1/128");
	});

	TEST("exact_mismatch", {
		/* 2001:db8::1 vs 2001:db8::2 */
		__u32 packet_ip[4];
		__u32 rule_ip[4];
		packet_ip[0] = bpf_htonl(0x20010db8);
		packet_ip[1] = 0;
		packet_ip[2] = 0;
		packet_ip[3] = bpf_htonl(0x1);
		rule_ip[0] = bpf_htonl(0x20010db8);
		rule_ip[1] = 0;
		rule_ip[2] = 0;
		rule_ip[3] = bpf_htonl(0x2);
		__u8 prefix_len = 128;
		
		int result = ipv6_matches(packet_ip, rule_ip, prefix_len);
		if (result)
			test_fatal("Expected IPv6 mismatch for different addresses");
	});

	TEST("prefix_64_match", {
		/* 2001:db8:1234:5678::1 matches 2001:db8:1234:5678::/64 */
		__u32 packet_ip[4];
		__u32 rule_ip[4];
		packet_ip[0] = bpf_htonl(0x20010db8);
		packet_ip[1] = bpf_htonl(0x12345678);
		packet_ip[2] = 0;
		packet_ip[3] = bpf_htonl(0x1);
		rule_ip[0] = bpf_htonl(0x20010db8);
		rule_ip[1] = bpf_htonl(0x12345678);
		rule_ip[2] = 0;
		rule_ip[3] = 0;
		__u8 prefix_len = 64;
		
		int result = ipv6_matches(packet_ip, rule_ip, prefix_len);
		if (!result)
			test_fatal("Expected /64 prefix match");
	});

	TEST("prefix_32_match", {
		/* 2001:db8:1234:5678::1 matches 2001:db8::/32 */
		__u32 packet_ip[4];
		__u32 rule_ip[4];
		packet_ip[0] = bpf_htonl(0x20010db8);
		packet_ip[1] = bpf_htonl(0x12345678);
		packet_ip[2] = 0;
		packet_ip[3] = bpf_htonl(0x1);
		rule_ip[0] = bpf_htonl(0x20010db8);
		rule_ip[1] = 0;
		rule_ip[2] = 0;
		rule_ip[3] = 0;
		__u8 prefix_len = 32;
		
		int result = ipv6_matches(packet_ip, rule_ip, prefix_len);
		if (!result)
			test_fatal("Expected /32 prefix match for 2001:db8::/32");
	});

	TEST("any_ipv6_match", {
		/* Any IPv6 address matches ::/0 */
		__u32 packet_ip[4];
		__u32 rule_ip[4];
		packet_ip[0] = bpf_htonl(0x20010db8);
		packet_ip[1] = bpf_htonl(0x12345678);
		packet_ip[2] = 0;
		packet_ip[3] = bpf_htonl(0x1);
		rule_ip[0] = 0;
		rule_ip[1] = 0;
		rule_ip[2] = 0;
		rule_ip[3] = 0;
		__u8 prefix_len = 0;
		
		int result = ipv6_matches(packet_ip, rule_ip, prefix_len);
		if (!result)
			test_fatal("Expected any IPv6 (::/0) to match");
	});

	test_finish();
}

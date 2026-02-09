/*
 * Common test utilities for BPF tests
 *
 * This module provides helper functions and utilities for testing BPF programs.
 */

// Constants matching the BPF program definitions
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;
pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_ANY: u8 = 255;

pub const PORT_ANY: u16 = 0;

pub fn cidr_to_mask(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else if prefix_len >= 32 {
        0xFFFFFFFF
    } else {
        0xFFFFFFFF << (32 - prefix_len)
    }
}

pub fn ip_matches(packet_ip: u32, rule_ip: u32, subnet_mask: u32) -> bool {
    if subnet_mask == 0xFFFFFFFF {
        packet_ip == rule_ip
    } else if subnet_mask == 0 {
        true
    } else {
        (packet_ip & subnet_mask) == (rule_ip & subnet_mask)
    }
}

pub fn port_matches(packet_port: u16, rule_port: u16) -> bool {
    rule_port == PORT_ANY || packet_port == rule_port
}

pub fn protocol_matches(packet_proto: u8, rule_proto: u8) -> bool {
    rule_proto == IPPROTO_ANY || rule_proto == packet_proto
}

pub fn ipv6_matches(packet_ip: &[u32; 4], rule_ip: &[u32; 4], prefix_len: u8) -> bool {
    if prefix_len == 0 {
        return true;
    }

    if prefix_len == 128 {
        return packet_ip[0] == rule_ip[0]
            && packet_ip[1] == rule_ip[1]
            && packet_ip[2] == rule_ip[2]
            && packet_ip[3] == rule_ip[3];
    }

    let mut remaining_bits = prefix_len;

    for i in 0..4 {
        if remaining_bits == 0 {
            break;
        }

        if remaining_bits >= 32 {
            if packet_ip[i] != rule_ip[i] {
                return false;
            }
            remaining_bits -= 32;
        } else {
            let mask = u32::to_be(0xFFFFFFFF << (32 - remaining_bits));
            if (packet_ip[i] & mask) != (rule_ip[i] & mask) {
                return false;
            }
            break;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cidr_to_mask() {
        assert_eq!(cidr_to_mask(32), 0xFFFFFFFF);
        assert_eq!(cidr_to_mask(24), 0xFFFFFF00);
        assert_eq!(cidr_to_mask(16), 0xFFFF0000);
        assert_eq!(cidr_to_mask(8), 0xFF000000);
        assert_eq!(cidr_to_mask(0), 0x00000000);
    }

    #[test]
    fn test_ip_matches_basic() {
        // Exact match
        assert!(ip_matches(0xC0A80101, 0xC0A80101, 0xFFFFFFFF));

        // Different IPs
        assert!(!ip_matches(0xC0A80101, 0xC0A80102, 0xFFFFFFFF));

        // CIDR /24
        assert!(ip_matches(0xC0A80101, 0xC0A80100, 0xFFFFFF00));

        // Match any
        assert!(ip_matches(0x01020304, 0x00000000, 0x00000000));
    }

    #[test]
    fn test_port_matches_basic() {
        assert!(port_matches(80, 80));
        assert!(!port_matches(80, 443));
        assert!(port_matches(12345, PORT_ANY));
    }

    #[test]
    fn test_protocol_matches_basic() {
        assert!(protocol_matches(IPPROTO_TCP, IPPROTO_TCP));
        assert!(!protocol_matches(IPPROTO_TCP, IPPROTO_UDP));
        assert!(protocol_matches(IPPROTO_ICMP, IPPROTO_ANY));
    }
}

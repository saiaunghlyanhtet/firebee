use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub enum Action {
    Allow,
    Drop,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub enum Direction {
    Ingress,
    Egress,
    Both,
}

impl Direction {
    pub fn to_u8(&self) -> u8 {
        match self {
            Direction::Ingress => 0,
            Direction::Egress => 1,
            Direction::Both => 2,
        }
    }

    pub fn from_u8(val: u8) -> Self {
        match val {
            0 => Direction::Ingress,
            1 => Direction::Egress,
            2 => Direction::Both,
            _ => Direction::Ingress,
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
#[allow(clippy::upper_case_acronyms)]
pub enum Protocol {
    TCP,
    UDP,
    ICMP,
    Any,
}

impl Protocol {
    pub fn to_u8(&self) -> u8 {
        match self {
            Protocol::TCP => 6,
            Protocol::UDP => 17,
            Protocol::ICMP => 1,
            Protocol::Any => 255,
        }
    }

    #[allow(dead_code)]
    pub fn from_u8(val: u8) -> Self {
        match val {
            6 => Protocol::TCP,
            17 => Protocol::UDP,
            1 => Protocol::ICMP,
            _ => Protocol::Any,
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Rule {
    pub ip: IpAddr,
    pub subnet_mask: Option<u8>,
    pub action: Action,
    pub protocol: Protocol,
    pub direction: Direction,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
}

impl Rule {
    pub fn get_subnet_mask_u32(&self) -> u32 {
        match self.subnet_mask {
            Some(prefix) => {
                if prefix == 0 {
                    0
                } else if prefix >= 32 {
                    0xFFFFFFFF
                } else {
                    !((1u32 << (32 - prefix)) - 1)
                }
            }
            None => 0xFFFFFFFF, // Exact match
        }
    }

    pub fn get_ipv6_prefix_len(&self) -> u8 {
        self.subnet_mask.unwrap_or(128)
    }

    #[allow(dead_code)]
    pub fn is_ipv6(&self) -> bool {
        matches!(self.ip, IpAddr::V6(_))
    }

    #[allow(dead_code)]
    pub fn as_ipv4(&self) -> Option<Ipv4Addr> {
        match self.ip {
            IpAddr::V4(addr) => Some(addr),
            IpAddr::V6(_) => None,
        }
    }

    #[allow(dead_code)]
    pub fn as_ipv6(&self) -> Option<Ipv6Addr> {
        match self.ip {
            IpAddr::V4(_) => None,
            IpAddr::V6(addr) => Some(addr),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_direction_to_u8() {
        assert_eq!(Direction::Ingress.to_u8(), 0);
        assert_eq!(Direction::Egress.to_u8(), 1);
        assert_eq!(Direction::Both.to_u8(), 2);
    }

    #[test]
    fn test_direction_from_u8() {
        assert_eq!(Direction::from_u8(0), Direction::Ingress);
        assert_eq!(Direction::from_u8(1), Direction::Egress);
        assert_eq!(Direction::from_u8(2), Direction::Both);
        assert_eq!(Direction::from_u8(99), Direction::Ingress); // Default case
    }

    #[test]
    fn test_direction_roundtrip() {
        let directions = vec![Direction::Ingress, Direction::Egress, Direction::Both];
        for direction in directions {
            let u8_val = direction.to_u8();
            let converted_back = Direction::from_u8(u8_val);
            assert_eq!(direction, converted_back);
        }
    }

    #[test]
    fn test_protocol_to_u8() {
        assert_eq!(Protocol::TCP.to_u8(), 6);
        assert_eq!(Protocol::UDP.to_u8(), 17);
        assert_eq!(Protocol::ICMP.to_u8(), 1);
        assert_eq!(Protocol::Any.to_u8(), 255);
    }

    #[test]
    fn test_protocol_from_u8() {
        assert_eq!(Protocol::from_u8(6), Protocol::TCP);
        assert_eq!(Protocol::from_u8(17), Protocol::UDP);
        assert_eq!(Protocol::from_u8(1), Protocol::ICMP);
        assert_eq!(Protocol::from_u8(255), Protocol::Any);
        assert_eq!(Protocol::from_u8(99), Protocol::Any); // Default case
    }

    #[test]
    fn test_protocol_roundtrip() {
        let protocols = vec![Protocol::TCP, Protocol::UDP, Protocol::ICMP, Protocol::Any];
        for protocol in protocols {
            let u8_val = protocol.to_u8();
            let converted_back = Protocol::from_u8(u8_val);
            assert_eq!(protocol, converted_back);
        }
    }

    #[test]
    fn test_subnet_mask_exact_match() {
        let rule = Rule {
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            subnet_mask: None,
            action: Action::Allow,
            protocol: Protocol::TCP,
            direction: Direction::Ingress,
            src_port: None,
            dst_port: None,
        };
        assert_eq!(rule.get_subnet_mask_u32(), 0xFFFFFFFF);
    }

    #[test]
    fn test_subnet_mask_zero() {
        let rule = Rule {
            ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            subnet_mask: Some(0),
            action: Action::Allow,
            protocol: Protocol::TCP,
            direction: Direction::Ingress,
            src_port: None,
            dst_port: None,
        };
        assert_eq!(rule.get_subnet_mask_u32(), 0);
    }

    #[test]
    fn test_subnet_mask_24() {
        let rule = Rule {
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)),
            subnet_mask: Some(24),
            action: Action::Allow,
            protocol: Protocol::TCP,
            direction: Direction::Ingress,
            src_port: None,
            dst_port: None,
        };
        // /24 = 255.255.255.0 = 0xFFFFFF00
        assert_eq!(rule.get_subnet_mask_u32(), 0xFFFFFF00);
    }

    #[test]
    fn test_subnet_mask_16() {
        let rule = Rule {
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)),
            subnet_mask: Some(16),
            action: Action::Allow,
            protocol: Protocol::TCP,
            direction: Direction::Ingress,
            src_port: None,
            dst_port: None,
        };
        // /16 = 255.255.0.0 = 0xFFFF0000
        assert_eq!(rule.get_subnet_mask_u32(), 0xFFFF0000);
    }

    #[test]
    fn test_subnet_mask_8() {
        let rule = Rule {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            subnet_mask: Some(8),
            action: Action::Allow,
            protocol: Protocol::TCP,
            direction: Direction::Ingress,
            src_port: None,
            dst_port: None,
        };
        // /8 = 255.0.0.0 = 0xFF000000
        assert_eq!(rule.get_subnet_mask_u32(), 0xFF000000);
    }

    #[test]
    fn test_subnet_mask_32() {
        let rule = Rule {
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            subnet_mask: Some(32),
            action: Action::Allow,
            protocol: Protocol::TCP,
            direction: Direction::Ingress,
            src_port: None,
            dst_port: None,
        };
        assert_eq!(rule.get_subnet_mask_u32(), 0xFFFFFFFF);
    }

    #[test]
    fn test_subnet_mask_greater_than_32() {
        let rule = Rule {
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            subnet_mask: Some(33),
            action: Action::Allow,
            protocol: Protocol::TCP,
            direction: Direction::Ingress,
            src_port: None,
            dst_port: None,
        };
        assert_eq!(rule.get_subnet_mask_u32(), 0xFFFFFFFF);
    }

    #[test]
    fn test_action_equality() {
        assert_eq!(Action::Allow, Action::Allow);
        assert_eq!(Action::Drop, Action::Drop);
        assert_ne!(Action::Allow, Action::Drop);
    }

    #[test]
    fn test_protocol_equality() {
        assert_eq!(Protocol::TCP, Protocol::TCP);
        assert_eq!(Protocol::UDP, Protocol::UDP);
        assert_ne!(Protocol::TCP, Protocol::UDP);
    }

    #[test]
    fn test_direction_equality() {
        assert_eq!(Direction::Ingress, Direction::Ingress);
        assert_eq!(Direction::Egress, Direction::Egress);
        assert_eq!(Direction::Both, Direction::Both);
        assert_ne!(Direction::Ingress, Direction::Egress);
    }

    #[test]
    fn test_rule_with_ports() {
        let rule = Rule {
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            subnet_mask: None,
            action: Action::Allow,
            protocol: Protocol::TCP,
            direction: Direction::Ingress,
            src_port: Some(8080),
            dst_port: Some(443),
        };
        assert_eq!(rule.src_port, Some(8080));
        assert_eq!(rule.dst_port, Some(443));
    }

    #[test]
    fn test_rule_clone() {
        let rule = Rule {
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            subnet_mask: Some(24),
            action: Action::Allow,
            protocol: Protocol::TCP,
            direction: Direction::Ingress,
            src_port: None,
            dst_port: None,
        };
        let cloned = rule.clone();
        assert_eq!(rule.ip, cloned.ip);
        assert_eq!(rule.subnet_mask, cloned.subnet_mask);
        assert_eq!(rule.action, cloned.action);
        assert_eq!(rule.protocol, cloned.protocol);
        assert_eq!(rule.direction, cloned.direction);
    }

    // IPv6 tests
    #[test]
    fn test_ipv6_is_ipv6() {
        let rule = Rule {
            ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            subnet_mask: Some(64),
            action: Action::Allow,
            protocol: Protocol::TCP,
            direction: Direction::Ingress,
            src_port: None,
            dst_port: None,
        };
        assert!(rule.is_ipv6());
        assert_eq!(rule.get_ipv6_prefix_len(), 64);
    }

    #[test]
    fn test_ipv4_is_not_ipv6() {
        let rule = Rule {
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            subnet_mask: Some(24),
            action: Action::Allow,
            protocol: Protocol::TCP,
            direction: Direction::Ingress,
            src_port: None,
            dst_port: None,
        };
        assert!(!rule.is_ipv6());
    }

    #[test]
    fn test_ipv6_default_prefix() {
        let rule = Rule {
            ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
            subnet_mask: None,
            action: Action::Drop,
            protocol: Protocol::Any,
            direction: Direction::Both,
            src_port: None,
            dst_port: None,
        };
        assert_eq!(rule.get_ipv6_prefix_len(), 128); // Default to exact match
    }

    #[test]
    fn test_as_ipv4() {
        let rule = Rule {
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            subnet_mask: None,
            action: Action::Allow,
            protocol: Protocol::TCP,
            direction: Direction::Ingress,
            src_port: None,
            dst_port: None,
        };
        assert_eq!(rule.as_ipv4(), Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(rule.as_ipv6(), None);
    }

    #[test]
    fn test_as_ipv6() {
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let rule = Rule {
            ip: IpAddr::V6(addr),
            subnet_mask: Some(64),
            action: Action::Allow,
            protocol: Protocol::TCP,
            direction: Direction::Ingress,
            src_port: None,
            dst_port: None,
        };
        assert_eq!(rule.as_ipv6(), Some(addr));
        assert_eq!(rule.as_ipv4(), None);
    }
}

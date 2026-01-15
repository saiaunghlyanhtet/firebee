use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub enum Action {
    Allow,
    Drop,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub enum Direction {
    Ingress,  // Incoming traffic
    Egress,   // Outgoing traffic
    Both,     // Both directions
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
            _ => Direction::Ingress, // Default to ingress
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
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
    pub ip: Ipv4Addr,
    pub subnet_mask: Option<u8>,  // CIDR prefix length (e.g., 24 for /24)
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
}

use crate::models::rule::{Action, Direction, Protocol, Rule};
use crate::policy::PolicyRule;
use libbpf_rs::{Map, MapCore};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// IPv4 structures (keep existing for backward compatibility)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RuleEntry {
    pub src_ip: u32,
    pub subnet_mask: u32,
    pub protocol: u8,
    pub action: u8,
    pub direction: u8,
    pub valid: u8,
    pub src_port: u16,
    pub dst_port: u16,
    pub _padding: [u8; 2],
}

// IPv6 structures (new)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RuleEntryV6 {
    pub src_ip: [u8; 16], // IPv6 address (128 bits)
    pub prefix_len: u8,   // CIDR prefix length (0-128)
    pub protocol: u8,
    pub action: u8,
    pub direction: u8,
    pub valid: u8,
    pub _padding: [u8; 3],
    pub src_port: u16,
    pub dst_port: u16,
    // No _padding2 - C struct is 28 bytes total
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct RuleKey {
    pub src_ip: u32,
    pub subnet_mask: u32,
    pub protocol: u8,
    pub src_port: u16,
    pub dst_port: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct RuleKeyV6 {
    pub src_ip: [u8; 16],
    pub prefix_len: u8,
    pub protocol: u8,
    pub src_port: u16,
    pub dst_port: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RuleStats {
    pub packets: u64,
    pub bytes: u64,
}

// IPv4 metadata
#[repr(C)]
#[derive(Debug, Clone)]
pub struct RuleMetadata {
    pub ip: u32,
    pub subnet_mask: u32,
    pub action: u8,
    pub protocol: u8,
    pub direction: u8,
    pub _padding: u8,
    pub src_port: u16,
    pub dst_port: u16,
    pub name: [u8; 64],
    pub description: [u8; 128],
}

// IPv6 metadata
#[repr(C)]
#[derive(Debug, Clone)]
pub struct RuleMetadataV6 {
    pub ip: [u8; 16],
    pub prefix_len: u8,
    pub action: u8,
    pub protocol: u8,
    pub direction: u8,
    pub src_port: u16,
    pub dst_port: u16,
    pub name: [u8; 64],
    pub description: [u8; 128],
    // Total: 216 bytes (matches C struct)
}

impl RuleMetadata {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ip: Ipv4Addr,
        subnet_mask: u32,
        action: u8,
        protocol: u8,
        direction: u8,
        src_port: Option<u16>,
        dst_port: Option<u16>,
        name: &str,
        description: Option<&str>,
    ) -> Self {
        let mut name_bytes = [0u8; 64];
        let mut desc_bytes = [0u8; 128];

        let name_len = name.len().min(63);
        name_bytes[..name_len].copy_from_slice(&name.as_bytes()[..name_len]);

        if let Some(desc) = description {
            let desc_len = desc.len().min(127);
            desc_bytes[..desc_len].copy_from_slice(&desc.as_bytes()[..desc_len]);
        }

        RuleMetadata {
            ip: u32::from_be_bytes(ip.octets()),
            subnet_mask,
            action,
            protocol,
            direction,
            _padding: 0,
            src_port: src_port.unwrap_or(0),
            dst_port: dst_port.unwrap_or(0),
            name: name_bytes,
            description: desc_bytes,
        }
    }

    pub fn get_name(&self) -> String {
        let end = self.name.iter().position(|&b| b == 0).unwrap_or(64);
        String::from_utf8_lossy(&self.name[..end]).to_string()
    }

    pub fn get_description(&self) -> Option<String> {
        let end = self.description.iter().position(|&b| b == 0).unwrap_or(128);
        if end == 0 {
            None
        } else {
            Some(String::from_utf8_lossy(&self.description[..end]).to_string())
        }
    }

    pub fn get_ip(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.ip)
    }

    pub fn get_cidr(&self) -> String {
        let ip = self.get_ip();
        if self.subnet_mask == 0xFFFFFFFF {
            ip.to_string()
        } else if self.subnet_mask == 0 {
            format!("{}/0", ip)
        } else {
            let prefix_len = self.subnet_mask.count_ones();
            format!("{}/{}", ip, prefix_len)
        }
    }

    pub fn to_policy_rule(&self) -> PolicyRule {
        PolicyRule {
            name: self.get_name(),
            ip: self.get_cidr(),
            action: if self.action == 0 {
                "drop".to_string()
            } else {
                "allow".to_string()
            },
            description: self.get_description(),
            protocol: match self.protocol {
                6 => "tcp".to_string(),
                17 => "udp".to_string(),
                1 => "icmp".to_string(),
                _ => "any".to_string(),
            },
            direction: match self.direction {
                0 => "ingress".to_string(),
                1 => "egress".to_string(),
                2 => "both".to_string(),
                _ => "ingress".to_string(),
            },
            src_port: if self.src_port == 0 {
                None
            } else {
                Some(self.src_port)
            },
            dst_port: if self.dst_port == 0 {
                None
            } else {
                Some(self.dst_port)
            },
        }
    }
}

impl RuleMetadataV6 {
    #[allow(dead_code)]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ip: Ipv6Addr,
        prefix_len: u8,
        action: u8,
        protocol: u8,
        direction: u8,
        src_port: Option<u16>,
        dst_port: Option<u16>,
        name: &str,
        description: Option<&str>,
    ) -> Self {
        let mut name_bytes = [0u8; 64];
        let mut desc_bytes = [0u8; 128];

        let name_len = name.len().min(63);
        name_bytes[..name_len].copy_from_slice(&name.as_bytes()[..name_len]);

        if let Some(desc) = description {
            let desc_len = desc.len().min(127);
            desc_bytes[..desc_len].copy_from_slice(&desc.as_bytes()[..desc_len]);
        }

        RuleMetadataV6 {
            ip: ip.octets(),
            prefix_len,
            action,
            protocol,
            direction,
            src_port: src_port.unwrap_or(0),
            dst_port: dst_port.unwrap_or(0),
            name: name_bytes,
            description: desc_bytes,
        }
    }

    #[allow(dead_code)]
    pub fn get_name(&self) -> String {
        let end = self.name.iter().position(|&b| b == 0).unwrap_or(64);
        String::from_utf8_lossy(&self.name[..end]).to_string()
    }

    #[allow(dead_code)]
    pub fn get_description(&self) -> Option<String> {
        let end = self.description.iter().position(|&b| b == 0).unwrap_or(128);
        if end == 0 {
            None
        } else {
            Some(String::from_utf8_lossy(&self.description[..end]).to_string())
        }
    }

    #[allow(dead_code)]
    pub fn get_ip(&self) -> Ipv6Addr {
        Ipv6Addr::from(self.ip)
    }

    #[allow(dead_code)]
    pub fn get_cidr(&self) -> String {
        let ip = self.get_ip();
        if self.prefix_len == 128 {
            ip.to_string()
        } else {
            format!("{}/{}", ip, self.prefix_len)
        }
    }

    #[allow(dead_code)]
    pub fn to_policy_rule(&self) -> PolicyRule {
        PolicyRule {
            name: self.get_name(),
            ip: self.get_cidr(),
            action: if self.action == 0 {
                "drop".to_string()
            } else {
                "allow".to_string()
            },
            description: self.get_description(),
            protocol: match self.protocol {
                6 => "tcp".to_string(),
                17 => "udp".to_string(),
                58 => "icmpv6".to_string(), // ICMPv6
                1 => "icmp".to_string(),
                _ => "any".to_string(),
            },
            direction: match self.direction {
                0 => "ingress".to_string(),
                1 => "egress".to_string(),
                2 => "both".to_string(),
                _ => "ingress".to_string(),
            },
            src_port: if self.src_port == 0 {
                None
            } else {
                Some(self.src_port)
            },
            dst_port: if self.dst_port == 0 {
                None
            } else {
                Some(self.dst_port)
            },
        }
    }
}

pub struct BpfMaps<'a> {
    pub rules: Map<'a>,
    pub log_events: Map<'a>,
    pub metadata: Map<'a>,
    pub stats: Map<'a>,
    // IPv6 maps
    pub rules_v6: Option<Map<'a>>,
    pub metadata_v6: Option<Map<'a>>,
    #[allow(dead_code)]
    pub stats_v6: Option<Map<'a>>,
}

impl<'a> BpfMaps<'a> {
    pub fn new(obj: &'a libbpf_rs::Object) -> Self {
        let mut rules_map = None;
        let mut metadata_map = None;
        let mut log_events_map = None;
        let mut stats_map = None;
        let mut rules_v6_map = None;
        let mut metadata_v6_map = None;
        let mut stats_v6_map = None;

        for map in obj.maps() {
            let name = map.name().to_string_lossy();
            match name.as_ref() {
                "rules_map" => rules_map = Some(map),
                "rule_metadata_map" => metadata_map = Some(map),
                "log_events" => log_events_map = Some(map),
                "rule_stats_map" => stats_map = Some(map),
                "rules_v6_map" => rules_v6_map = Some(map),
                "rule_metadata_v6_map" => metadata_v6_map = Some(map),
                "rule_stats_v6_map" => stats_v6_map = Some(map),
                _ => {}
            }
        }

        let rules = rules_map.expect("rules_map not found");
        let metadata = metadata_map.expect("rule_metadata_map not found");
        let log_events = log_events_map.expect("log_events not found");
        let stats = stats_map.expect("rule_stats_map not found");

        BpfMaps {
            rules,
            log_events,
            metadata,
            stats,
            rules_v6: rules_v6_map,
            metadata_v6: metadata_v6_map,
            stats_v6: stats_v6_map,
        }
    }

    pub fn update_rule(&self, rule: &Rule, action: u8) -> Result<(), libbpf_rs::Error> {
        match rule.ip {
            IpAddr::V4(ipv4) => self.update_rule_v4(ipv4, rule, action),
            IpAddr::V6(ipv6) => self.update_rule_v6(ipv6, rule, action),
        }
    }

    fn update_rule_v4(
        &self,
        ipv4: Ipv4Addr,
        rule: &Rule,
        action: u8,
    ) -> Result<(), libbpf_rs::Error> {
        log::info!("Updating IPv4 rule for IP {} with action {}", ipv4, action);

        let ip_u32 = u32::from_be_bytes(ipv4.octets());
        let subnet_mask = rule.get_subnet_mask_u32();

        // Create a rule entry for the array map
        let entry = RuleEntry {
            src_ip: ip_u32,
            subnet_mask,
            protocol: rule.protocol.to_u8(),
            action,
            direction: rule.direction.to_u8(),
            valid: 1,
            src_port: rule.src_port.unwrap_or(0),
            dst_port: rule.dst_port.unwrap_or(0),
            _padding: [0; 2],
        };

        let entry_bytes = unsafe {
            std::slice::from_raw_parts(
                &entry as *const RuleEntry as *const u8,
                std::mem::size_of::<RuleEntry>(),
            )
        };

        // Find first empty slot or update existing rule
        let mut slot_index: Option<u32> = None;

        for i in 0..1024u32 {
            let i_bytes = i.to_ne_bytes();
            if let Some(value) = self.rules.lookup(&i_bytes, libbpf_rs::MapFlags::ANY)? {
                if value.len() >= std::mem::size_of::<RuleEntry>() {
                    let existing = unsafe { std::ptr::read(value.as_ptr() as *const RuleEntry) };

                    // Check if this is the same rule (update case)
                    if existing.valid == 1
                        && existing.src_ip == ip_u32
                        && existing.subnet_mask == subnet_mask
                        && existing.protocol == rule.protocol.to_u8()
                        && existing.direction == rule.direction.to_u8()
                        && existing.src_port == rule.src_port.unwrap_or(0)
                        && existing.dst_port == rule.dst_port.unwrap_or(0)
                    {
                        slot_index = Some(i);
                        break;
                    }

                    // Track first empty slot
                    if existing.valid == 0 && slot_index.is_none() {
                        slot_index = Some(i);
                    }
                }
            } else {
                // Empty slot found
                if slot_index.is_none() {
                    slot_index = Some(i);
                }
            }
        }

        let index = slot_index.ok_or_else(|| {
            libbpf_rs::Error::from(std::io::Error::other("Rules map is full (max 1024 rules)"))
        })?;

        let index_bytes = index.to_ne_bytes();
        self.rules
            .update(&index_bytes, entry_bytes, libbpf_rs::MapFlags::ANY)?;

        log::info!(
            "Rule updated successfully for IP {} at index {}",
            rule.ip,
            index
        );
        Ok(())
    }

    pub fn remove_rule(&self, rule: &Rule) -> Result<(), libbpf_rs::Error> {
        match rule.ip {
            IpAddr::V4(ipv4) => self.remove_rule_v4(ipv4, rule),
            IpAddr::V6(ipv6) => self.remove_rule_v6(ipv6, rule),
        }
    }

    fn remove_rule_v4(&self, ipv4: Ipv4Addr, rule: &Rule) -> Result<(), libbpf_rs::Error> {
        log::info!("Removing IPv4 rule for IP {}", ipv4);

        let ip_u32 = u32::from_be_bytes(ipv4.octets());
        let subnet_mask = rule.get_subnet_mask_u32();

        // Find and invalidate the matching rule entry
        for i in 0..1024u32 {
            let i_bytes = i.to_ne_bytes();
            if let Some(value) = self.rules.lookup(&i_bytes, libbpf_rs::MapFlags::ANY)? {
                if value.len() >= std::mem::size_of::<RuleEntry>() {
                    let existing = unsafe { std::ptr::read(value.as_ptr() as *const RuleEntry) };

                    if existing.valid == 1
                        && existing.src_ip == ip_u32
                        && existing.subnet_mask == subnet_mask
                        && existing.protocol == rule.protocol.to_u8()
                        && existing.src_port == rule.src_port.unwrap_or(0)
                        && existing.dst_port == rule.dst_port.unwrap_or(0)
                    {
                        // Mark as invalid
                        let mut entry = existing;
                        entry.valid = 0;

                        let entry_bytes = unsafe {
                            std::slice::from_raw_parts(
                                &entry as *const RuleEntry as *const u8,
                                std::mem::size_of::<RuleEntry>(),
                            )
                        };

                        self.rules
                            .update(&i_bytes, entry_bytes, libbpf_rs::MapFlags::ANY)?;
                        log::info!(
                            "IPv4 rule removed successfully for IP {} from index {}",
                            ipv4,
                            i
                        );
                        return Ok(());
                    }
                }
            }
        }

        Err(libbpf_rs::Error::from(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("IPv4 rule not found for IP {}", ipv4),
        )))
    }

    fn remove_rule_v6(&self, ipv6: Ipv6Addr, rule: &Rule) -> Result<(), libbpf_rs::Error> {
        let rules_v6 = self
            .rules_v6
            .as_ref()
            .ok_or_else(|| std::io::Error::other("IPv6 rules map not available"))?;

        log::info!("Removing IPv6 rule for IP {}", ipv6);

        let prefix_len = rule.get_ipv6_prefix_len();

        // Find and invalidate the matching rule entry
        for i in 0..1024u32 {
            let i_bytes = i.to_ne_bytes();
            if let Some(value) = rules_v6.lookup(&i_bytes, libbpf_rs::MapFlags::ANY)? {
                if value.len() >= std::mem::size_of::<RuleEntryV6>() {
                    let existing = unsafe { std::ptr::read(value.as_ptr() as *const RuleEntryV6) };

                    if existing.valid == 1
                        && existing.src_ip == ipv6.octets()
                        && existing.prefix_len == prefix_len
                        && existing.protocol == rule.protocol.to_u8()
                        && existing.src_port == rule.src_port.unwrap_or(0)
                        && existing.dst_port == rule.dst_port.unwrap_or(0)
                    {
                        // Mark as invalid
                        let mut entry = existing;
                        entry.valid = 0;

                        let entry_bytes = unsafe {
                            std::slice::from_raw_parts(
                                &entry as *const RuleEntryV6 as *const u8,
                                std::mem::size_of::<RuleEntryV6>(),
                            )
                        };

                        rules_v6.update(&i_bytes, entry_bytes, libbpf_rs::MapFlags::ANY)?;
                        log::info!(
                            "IPv6 rule removed successfully for IP {} from index {}",
                            ipv6,
                            i
                        );
                        return Ok(());
                    }
                }
            }
        }

        Err(libbpf_rs::Error::from(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("IPv6 rule not found for IP {}", ipv6),
        )))
    }

    fn update_rule_v6(
        &self,
        ipv6: Ipv6Addr,
        rule: &Rule,
        action: u8,
    ) -> Result<(), libbpf_rs::Error> {
        let rules_v6 = self
            .rules_v6
            .as_ref()
            .ok_or_else(|| std::io::Error::other("IPv6 rules map not available"))?;

        log::info!("Updating IPv6 rule for IP {} with action {}", ipv6, action);

        let prefix_len = rule.get_ipv6_prefix_len();

        // Create a rule entry for the array map
        let entry = RuleEntryV6 {
            src_ip: ipv6.octets(),
            prefix_len,
            protocol: rule.protocol.to_u8(),
            action,
            direction: rule.direction.to_u8(),
            valid: 1,
            _padding: [0; 3],
            src_port: rule.src_port.unwrap_or(0),
            dst_port: rule.dst_port.unwrap_or(0),
        };

        let entry_bytes = unsafe {
            std::slice::from_raw_parts(
                &entry as *const RuleEntryV6 as *const u8,
                std::mem::size_of::<RuleEntryV6>(),
            )
        };

        // Find first empty slot or update existing rule
        let mut slot_index: Option<u32> = None;
        let mut slots_checked = 0u32;
        let mut valid_slots = 0u32;
        let mut none_count = 0u32;
        let mut short_value_count = 0u32;

        for i in 0..1024u32 {
            slots_checked += 1;
            let i_bytes = i.to_ne_bytes();
            if let Some(value) = rules_v6.lookup(&i_bytes, libbpf_rs::MapFlags::ANY)? {
                if value.len() >= std::mem::size_of::<RuleEntryV6>() {
                    let existing = unsafe { std::ptr::read(value.as_ptr() as *const RuleEntryV6) };

                    if existing.valid == 1 {
                        valid_slots += 1;
                    }

                    // Check if this is the same rule (update case)
                    if existing.valid == 1
                        && existing.src_ip == ipv6.octets()
                        && existing.prefix_len == prefix_len
                        && existing.protocol == rule.protocol.to_u8()
                        && existing.direction == rule.direction.to_u8()
                        && existing.src_port == rule.src_port.unwrap_or(0)
                        && existing.dst_port == rule.dst_port.unwrap_or(0)
                    {
                        slot_index = Some(i);
                        log::info!("Found existing IPv6 rule at index {}", i);
                        break;
                    }

                    // Track first empty slot
                    if existing.valid == 0 && slot_index.is_none() {
                        slot_index = Some(i);
                        log::info!("Found empty IPv6 slot (valid=0) at index {}", i);
                    }
                } else {
                    short_value_count += 1;
                    if i == 0 {
                        log::warn!(
                            "IPv6 map entry 0 has unexpected size: {} bytes (expected {})",
                            value.len(),
                            std::mem::size_of::<RuleEntryV6>()
                        );
                    }
                }
            } else {
                // Empty slot found (no entry exists yet)
                none_count += 1;
                if slot_index.is_none() {
                    slot_index = Some(i);
                    log::info!("Found uninitialized IPv6 slot at index {}", i);
                }
            }
        }

        log::info!(
            "IPv6 map scan complete: checked={}, valid={}, none={}, short={}, slot={:?}",
            slots_checked,
            valid_slots,
            none_count,
            short_value_count,
            slot_index
        );

        let index = slot_index.ok_or_else(|| {
            libbpf_rs::Error::from(std::io::Error::other(format!(
                "IPv6 rules map is full (max 1024 rules, {} currently valid)",
                valid_slots
            )))
        })?;

        let index_bytes = index.to_ne_bytes();
        rules_v6.update(&index_bytes, entry_bytes, libbpf_rs::MapFlags::ANY)?;

        log::info!(
            "IPv6 rule updated successfully for IP {} at index {}",
            ipv6,
            index
        );
        Ok(())
    }

    #[allow(dead_code)]
    pub fn get_all_rules(&self) -> Result<Vec<Rule>, libbpf_rs::Error> {
        let mut rules = Vec::new();

        // Iterate through array map entries
        for i in 0..1024u32 {
            let i_bytes = i.to_ne_bytes();
            if let Some(value) = self.rules.lookup(&i_bytes, libbpf_rs::MapFlags::ANY)? {
                if value.len() >= std::mem::size_of::<RuleEntry>() {
                    let entry = unsafe { std::ptr::read(value.as_ptr() as *const RuleEntry) };

                    // Only include valid entries
                    if entry.valid == 0 {
                        continue;
                    }

                    let ip = Ipv4Addr::from(entry.src_ip);
                    let action = if entry.action == 0 {
                        Action::Drop
                    } else {
                        Action::Allow
                    };

                    let protocol = Protocol::from_u8(entry.protocol);
                    let subnet_mask = if entry.subnet_mask == 0xFFFFFFFF {
                        None
                    } else if entry.subnet_mask == 0 {
                        Some(0)
                    } else {
                        Some(entry.subnet_mask.count_ones() as u8)
                    };

                    rules.push(Rule {
                        ip: IpAddr::V4(ip),
                        subnet_mask,
                        action,
                        protocol,
                        direction: Direction::from_u8(entry.direction),
                        src_port: if entry.src_port == 0 {
                            None
                        } else {
                            Some(entry.src_port)
                        },
                        dst_port: if entry.dst_port == 0 {
                            None
                        } else {
                            Some(entry.dst_port)
                        },
                    });
                }
            }
        }

        log::info!("Loaded {} existing rules from eBPF map", rules.len());
        Ok(rules)
    }

    // Metadata map operations
    pub fn add_rule_metadata(
        &self,
        name: &str,
        rule: &Rule,
        action: u8,
        description: Option<&str>,
    ) -> Result<(), libbpf_rs::Error> {
        match rule.ip {
            IpAddr::V4(ipv4) => {
                let subnet_mask = rule.get_subnet_mask_u32();
                let metadata = RuleMetadata::new(
                    ipv4,
                    subnet_mask,
                    action,
                    rule.protocol.to_u8(),
                    rule.direction.to_u8(),
                    rule.src_port,
                    rule.dst_port,
                    name,
                    description,
                );
                let metadata_bytes = unsafe {
                    std::slice::from_raw_parts(
                        &metadata as *const RuleMetadata as *const u8,
                        std::mem::size_of::<RuleMetadata>(),
                    )
                };

                let mut key_bytes = [0u8; 64];
                let name_len = name.len().min(63);
                key_bytes[..name_len].copy_from_slice(&name.as_bytes()[..name_len]);

                self.metadata
                    .update(&key_bytes[..], metadata_bytes, libbpf_rs::MapFlags::ANY)?;
                log::info!("Added IPv4 metadata for rule '{}'", name);
                Ok(())
            }
            IpAddr::V6(ipv6) => {
                let metadata_v6_map = self
                    .metadata_v6
                    .as_ref()
                    .ok_or_else(|| std::io::Error::other("IPv6 metadata map not available"))?;

                let prefix_len = rule.get_ipv6_prefix_len();
                let metadata = RuleMetadataV6::new(
                    ipv6,
                    prefix_len,
                    action,
                    rule.protocol.to_u8(),
                    rule.direction.to_u8(),
                    rule.src_port,
                    rule.dst_port,
                    name,
                    description,
                );

                let metadata_bytes = unsafe {
                    std::slice::from_raw_parts(
                        &metadata as *const RuleMetadataV6 as *const u8,
                        std::mem::size_of::<RuleMetadataV6>(),
                    )
                };

                let mut key_bytes = [0u8; 64];
                let name_len = name.len().min(63);
                key_bytes[..name_len].copy_from_slice(&name.as_bytes()[..name_len]);

                metadata_v6_map.update(&key_bytes[..], metadata_bytes, libbpf_rs::MapFlags::ANY)?;
                log::info!("Added IPv6 metadata for rule '{}'", name);
                Ok(())
            }
        }
    }

    pub fn get_rule_metadata(&self, name: &str) -> Result<Option<PolicyRule>, libbpf_rs::Error> {
        let mut key_bytes = [0u8; 64];
        let name_len = name.len().min(63);
        key_bytes[..name_len].copy_from_slice(&name.as_bytes()[..name_len]);

        // Try IPv4 metadata first
        if let Some(value) = self
            .metadata
            .lookup(&key_bytes[..], libbpf_rs::MapFlags::ANY)?
        {
            if value.len() >= std::mem::size_of::<RuleMetadata>() {
                let metadata = unsafe { std::ptr::read(value.as_ptr() as *const RuleMetadata) };
                return Ok(Some(metadata.to_policy_rule()));
            }
        }

        // Try IPv6 metadata if IPv4 not found
        if let Some(metadata_v6) = &self.metadata_v6 {
            if let Some(value) = metadata_v6.lookup(&key_bytes[..], libbpf_rs::MapFlags::ANY)? {
                if value.len() >= std::mem::size_of::<RuleMetadataV6>() {
                    let metadata_v6 =
                        unsafe { std::ptr::read(value.as_ptr() as *const RuleMetadataV6) };
                    return Ok(Some(metadata_v6.to_policy_rule()));
                }
            }
        }

        Ok(None)
    }

    pub fn delete_rule_metadata(&self, name: &str) -> Result<(), libbpf_rs::Error> {
        let mut key_bytes = [0u8; 64];
        let name_len = name.len().min(63);
        key_bytes[..name_len].copy_from_slice(&name.as_bytes()[..name_len]);

        // Try to delete from IPv4 metadata
        let ipv4_result = self.metadata.delete(&key_bytes[..]);

        // Also try IPv6 metadata
        if let Some(metadata_v6) = &self.metadata_v6 {
            let ipv6_result = metadata_v6.delete(&key_bytes[..]);
            // If IPv6 deletion succeeded, that's fine
            if ipv6_result.is_ok() {
                log::info!("Deleted IPv6 metadata for rule '{}'", name);
                return Ok(());
            }
        }

        // If IPv4 deletion succeeded, return Ok
        if ipv4_result.is_ok() {
            log::info!("Deleted IPv4 metadata for rule '{}'", name);
            return Ok(());
        }

        // Both failed, return the IPv4 error
        ipv4_result
    }

    pub fn list_all_metadata(&self) -> Result<Vec<PolicyRule>, libbpf_rs::Error> {
        let mut rules = Vec::new();

        // Get IPv4 rules
        for key in self.metadata.keys() {
            if let Some(value) = self.metadata.lookup(&key, libbpf_rs::MapFlags::ANY)? {
                if value.len() >= std::mem::size_of::<RuleMetadata>() {
                    let metadata = unsafe { std::ptr::read(value.as_ptr() as *const RuleMetadata) };
                    rules.push(metadata.to_policy_rule());
                }
            }
        }

        // Get IPv6 rules
        if let Some(metadata_v6) = &self.metadata_v6 {
            for key in metadata_v6.keys() {
                if let Some(value) = metadata_v6.lookup(&key, libbpf_rs::MapFlags::ANY)? {
                    if value.len() >= std::mem::size_of::<RuleMetadataV6>() {
                        let metadata =
                            unsafe { std::ptr::read(value.as_ptr() as *const RuleMetadataV6) };
                        rules.push(metadata.to_policy_rule());
                    }
                }
            }
        }

        Ok(rules)
    }

    /// Get statistics for a specific rule by index
    pub fn get_rule_stats(&self, index: u32) -> Result<Option<RuleStats>, libbpf_rs::Error> {
        let index_bytes = index.to_ne_bytes();

        if let Some(value) = self.stats.lookup(&index_bytes, libbpf_rs::MapFlags::ANY)? {
            if value.len() >= std::mem::size_of::<RuleStats>() {
                let stats = unsafe { std::ptr::read(value.as_ptr() as *const RuleStats) };
                return Ok(Some(stats));
            }
        }
        Ok(None)
    }

    /// Get statistics for all rules
    #[allow(dead_code)]
    pub fn get_all_stats(&self) -> Result<Vec<(u32, RuleStats)>, libbpf_rs::Error> {
        let mut stats_list = Vec::new();

        for i in 0..1024u32 {
            let i_bytes = i.to_ne_bytes();
            if let Some(value) = self.stats.lookup(&i_bytes, libbpf_rs::MapFlags::ANY)? {
                if value.len() >= std::mem::size_of::<RuleStats>() {
                    let stats = unsafe { std::ptr::read(value.as_ptr() as *const RuleStats) };
                    // Only include non-zero stats
                    if stats.packets > 0 || stats.bytes > 0 {
                        stats_list.push((i, stats));
                    }
                }
            }
        }

        Ok(stats_list)
    }

    /// Reset statistics for a specific rule
    pub fn reset_rule_stats(&self, index: u32) -> Result<(), libbpf_rs::Error> {
        let index_bytes = index.to_ne_bytes();
        let zero_stats = RuleStats {
            packets: 0,
            bytes: 0,
        };

        let stats_bytes = unsafe {
            std::slice::from_raw_parts(
                &zero_stats as *const RuleStats as *const u8,
                std::mem::size_of::<RuleStats>(),
            )
        };

        self.stats
            .update(&index_bytes, stats_bytes, libbpf_rs::MapFlags::ANY)?;
        Ok(())
    }

    /// Reset all statistics
    pub fn reset_all_stats(&self) -> Result<(), libbpf_rs::Error> {
        for i in 0..1024u32 {
            self.reset_rule_stats(i)?;
        }
        Ok(())
    }

    /// Get statistics mapped to rule names
    /// Returns a HashMap of rule_name -> (packets, bytes)
    pub fn get_stats_by_name(
        &self,
    ) -> Result<std::collections::HashMap<String, (u64, u64)>, libbpf_rs::Error> {
        use std::collections::HashMap;

        let mut stats_map = HashMap::new();

        // First, build a map of rule attributes to index
        let mut rule_index_map: HashMap<(u32, u32, u8, u16, u16), u32> = HashMap::new();

        for i in 0..1024u32 {
            let i_bytes = i.to_ne_bytes();
            if let Some(value) = self.rules.lookup(&i_bytes, libbpf_rs::MapFlags::ANY)? {
                if value.len() >= std::mem::size_of::<RuleEntry>() {
                    let entry = unsafe { std::ptr::read(value.as_ptr() as *const RuleEntry) };

                    if entry.valid == 1 {
                        let key = (
                            entry.src_ip,
                            entry.subnet_mask,
                            entry.protocol,
                            entry.src_port,
                            entry.dst_port,
                        );
                        rule_index_map.insert(key, i);
                    }
                }
            }
        }

        // Now iterate through metadata and match with stats
        for key in self.metadata.keys() {
            if let Some(value) = self.metadata.lookup(&key, libbpf_rs::MapFlags::ANY)? {
                if value.len() >= std::mem::size_of::<RuleMetadata>() {
                    let metadata = unsafe { std::ptr::read(value.as_ptr() as *const RuleMetadata) };

                    let rule_key = (
                        metadata.ip,
                        metadata.subnet_mask,
                        metadata.protocol,
                        metadata.src_port,
                        metadata.dst_port,
                    );

                    if let Some(&index) = rule_index_map.get(&rule_key) {
                        if let Ok(Some(stats)) = self.get_rule_stats(index) {
                            let name = metadata.get_name();
                            stats_map.insert(name, (stats.packets, stats.bytes));
                        }
                    }
                }
            }
        }

        Ok(stats_map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_metadata_new() {
        let metadata = RuleMetadata::new(
            Ipv4Addr::new(192, 168, 1, 1),
            0xFFFFFFFF,
            1,
            6,
            0,
            Some(8080),
            Some(443),
            "test_rule",
            Some("Test description"),
        );

        assert_eq!(metadata.action, 1);
        assert_eq!(metadata.protocol, 6);
        assert_eq!(metadata.direction, 0);
        assert_eq!(metadata.src_port, 8080);
        assert_eq!(metadata.dst_port, 443);
    }

    #[test]
    fn test_rule_metadata_get_name() {
        let metadata = RuleMetadata::new(
            Ipv4Addr::new(192, 168, 1, 1),
            0xFFFFFFFF,
            1,
            6,
            0,
            None,
            None,
            "my_firewall_rule",
            None,
        );

        assert_eq!(metadata.get_name(), "my_firewall_rule");
    }

    #[test]
    fn test_rule_metadata_long_name_truncation() {
        let long_name = "a".repeat(100);
        let metadata = RuleMetadata::new(
            Ipv4Addr::new(192, 168, 1, 1),
            0xFFFFFFFF,
            1,
            6,
            0,
            None,
            None,
            &long_name,
            None,
        );

        let result_name = metadata.get_name();
        assert!(result_name.len() <= 63);
        assert_eq!(result_name, "a".repeat(63));
    }

    #[test]
    fn test_rule_metadata_get_description_some() {
        let metadata = RuleMetadata::new(
            Ipv4Addr::new(192, 168, 1, 1),
            0xFFFFFFFF,
            1,
            6,
            0,
            None,
            None,
            "test",
            Some("Block malicious traffic"),
        );

        assert_eq!(
            metadata.get_description(),
            Some("Block malicious traffic".to_string())
        );
    }

    #[test]
    fn test_rule_metadata_get_description_none() {
        let metadata = RuleMetadata::new(
            Ipv4Addr::new(192, 168, 1, 1),
            0xFFFFFFFF,
            1,
            6,
            0,
            None,
            None,
            "test",
            None,
        );

        assert_eq!(metadata.get_description(), None);
    }

    #[test]
    fn test_rule_metadata_long_description_truncation() {
        let long_desc = "b".repeat(200);
        let metadata = RuleMetadata::new(
            Ipv4Addr::new(192, 168, 1, 1),
            0xFFFFFFFF,
            1,
            6,
            0,
            None,
            None,
            "test",
            Some(&long_desc),
        );

        let result_desc = metadata.get_description().unwrap();
        assert!(result_desc.len() <= 127);
        assert_eq!(result_desc, "b".repeat(127));
    }

    #[test]
    fn test_rule_metadata_get_ip() {
        let metadata = RuleMetadata::new(
            Ipv4Addr::new(10, 0, 0, 1),
            0xFFFFFFFF,
            1,
            6,
            0,
            None,
            None,
            "test",
            None,
        );

        assert_eq!(metadata.get_ip(), Ipv4Addr::new(10, 0, 0, 1));
    }

    #[test]
    fn test_rule_metadata_get_cidr_exact_match() {
        let metadata = RuleMetadata::new(
            Ipv4Addr::new(192, 168, 1, 1),
            0xFFFFFFFF,
            1,
            6,
            0,
            None,
            None,
            "test",
            None,
        );

        assert_eq!(metadata.get_cidr(), "192.168.1.1");
    }

    #[test]
    fn test_rule_metadata_get_cidr_with_prefix() {
        let metadata = RuleMetadata::new(
            Ipv4Addr::new(192, 168, 1, 0),
            0xFFFFFF00, // /24
            1,
            6,
            0,
            None,
            None,
            "test",
            None,
        );

        assert_eq!(metadata.get_cidr(), "192.168.1.0/24");
    }

    #[test]
    fn test_rule_metadata_get_cidr_zero_prefix() {
        let metadata = RuleMetadata::new(
            Ipv4Addr::new(0, 0, 0, 0),
            0,
            1,
            6,
            0,
            None,
            None,
            "test",
            None,
        );

        assert_eq!(metadata.get_cidr(), "0.0.0.0/0");
    }

    #[test]
    fn test_rule_metadata_to_policy_rule_allow() {
        let metadata = RuleMetadata::new(
            Ipv4Addr::new(192, 168, 1, 1),
            0xFFFFFFFF,
            1, // allow
            6, // tcp
            0, // ingress
            Some(8080),
            Some(443),
            "allow_https",
            Some("Allow HTTPS traffic"),
        );

        let policy = metadata.to_policy_rule();
        assert_eq!(policy.name, "allow_https");
        assert_eq!(policy.ip, "192.168.1.1");
        assert_eq!(policy.action, "allow");
        assert_eq!(policy.protocol, "tcp");
        assert_eq!(policy.direction, "ingress");
        assert_eq!(policy.src_port, Some(8080));
        assert_eq!(policy.dst_port, Some(443));
        assert_eq!(policy.description, Some("Allow HTTPS traffic".to_string()));
    }

    #[test]
    fn test_rule_metadata_to_policy_rule_drop() {
        let metadata = RuleMetadata::new(
            Ipv4Addr::new(10, 0, 0, 1),
            0xFFFFFFFF,
            0,  // drop
            17, // udp
            1,  // egress
            None,
            None,
            "drop_udp",
            None,
        );

        let policy = metadata.to_policy_rule();
        assert_eq!(policy.action, "drop");
        assert_eq!(policy.protocol, "udp");
        assert_eq!(policy.direction, "egress");
        assert_eq!(policy.src_port, None);
        assert_eq!(policy.dst_port, None);
        assert_eq!(policy.description, None);
    }

    #[test]
    fn test_rule_metadata_protocol_conversions() {
        let test_cases = vec![
            (6, "tcp"),
            (17, "udp"),
            (1, "icmp"),
            (255, "any"),
            (99, "any"), // unknown defaults to any
        ];

        for (protocol_u8, expected) in test_cases {
            let metadata = RuleMetadata::new(
                Ipv4Addr::new(192, 168, 1, 1),
                0xFFFFFFFF,
                1,
                protocol_u8,
                0,
                None,
                None,
                "test",
                None,
            );

            let policy = metadata.to_policy_rule();
            assert_eq!(policy.protocol, expected);
        }
    }

    #[test]
    fn test_rule_metadata_direction_conversions() {
        let test_cases = vec![
            (0, "ingress"),
            (1, "egress"),
            (2, "both"),
            (99, "ingress"), // unknown defaults to ingress
        ];

        for (direction_u8, expected) in test_cases {
            let metadata = RuleMetadata::new(
                Ipv4Addr::new(192, 168, 1, 1),
                0xFFFFFFFF,
                1,
                6,
                direction_u8,
                None,
                None,
                "test",
                None,
            );

            let policy = metadata.to_policy_rule();
            assert_eq!(policy.direction, expected);
        }
    }

    #[test]
    fn test_rule_metadata_port_zero_means_none() {
        let metadata = RuleMetadata::new(
            Ipv4Addr::new(192, 168, 1, 1),
            0xFFFFFFFF,
            1,
            6,
            0,
            None,
            None,
            "test",
            None,
        );

        let policy = metadata.to_policy_rule();
        assert_eq!(policy.src_port, None);
        assert_eq!(policy.dst_port, None);
    }

    #[test]
    fn test_rule_entry_fields() {
        let entry = RuleEntry {
            src_ip: u32::from_be_bytes([192, 168, 1, 1]),
            subnet_mask: 0xFFFFFFFF,
            protocol: 6,
            action: 1,
            direction: 0,
            valid: 1,
            src_port: 8080,
            dst_port: 443,
            _padding: [0; 2],
        };
        assert_eq!(entry.action, 1);
        assert_eq!(entry.protocol, 6);
        assert_eq!(entry.src_port, 8080);
        assert_eq!(entry.dst_port, 443);
        assert_eq!(entry.valid, 1);
    }

    #[test]
    fn test_rule_stats_default() {
        let stats = RuleStats {
            packets: 0,
            bytes: 0,
        };
        assert_eq!(stats.packets, 0);
        assert_eq!(stats.bytes, 0);
    }

    #[test]
    fn test_rule_key_fields() {
        let key = RuleKey {
            src_ip: u32::from_be_bytes([192, 168, 1, 1]),
            subnet_mask: 0xFFFFFFFF,
            protocol: 6,
            src_port: 8080,
            dst_port: 443,
        };
        assert_eq!(key.src_ip, u32::from_be_bytes([192, 168, 1, 1]));
        assert_eq!(key.subnet_mask, 0xFFFFFFFF);
        assert_eq!(key.protocol, 6);
        assert_eq!(key.src_port, 8080);
        assert_eq!(key.dst_port, 443);
    }
}

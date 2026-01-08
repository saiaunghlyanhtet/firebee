use libbpf_rs::{Map, MapCore};
use std::net::Ipv4Addr;
use crate::models::rule::{Action, Rule};
use crate::policy::PolicyRule;

#[repr(C)]
#[derive(Debug, Clone)]
pub struct RuleMetadata {
    pub ip: u32,
    pub action: u8,
    pub name: [u8; 64],
    pub description: [u8; 128],
}

impl RuleMetadata {
    pub fn new(ip: Ipv4Addr, action: u8, name: &str, description: Option<&str>) -> Self {
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
            action,
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
    
    pub fn to_policy_rule(&self) -> PolicyRule {
        PolicyRule {
            name: self.get_name(),
            ip: self.get_ip().to_string(),
            action: if self.action == 0 { "drop".to_string() } else { "allow".to_string() },
            description: self.get_description(),
        }
    }
}

pub struct BpfMaps<'a> {
    pub rules: Map<'a>,
    pub log_events: Map<'a>,
    pub metadata: Map<'a>,
}

impl<'a> BpfMaps<'a> {
    pub fn new(obj: &'a libbpf_rs::Object) -> Self {
        let mut rules_map = None;
        let mut metadata_map = None;
        let mut log_events_map = None;
        
        for map in obj.maps() {
            let name = map.name().to_string_lossy();
            match name.as_ref() {
                "rules_map" => rules_map = Some(map),
                "rule_metadata_map" => metadata_map = Some(map),
                "log_events" => log_events_map = Some(map),
                _ => {}
            }
        }
        
        let rules = rules_map.expect("rules_map not found");
        let metadata = metadata_map.expect("rule_metadata_map not found");
        let log_events = log_events_map.expect("log_events not found");
        
        BpfMaps { rules, log_events, metadata }
    }

    pub fn update_rule(&self, ip: Ipv4Addr, action: u32) -> Result<(), libbpf_rs::Error> {
        log::info!("Updating rule for IP {} with action {}", ip, action);
        
        let ip_bytes = ip.octets();
        let ip_u32 = u32::from_be_bytes(ip_bytes);
        
        let key_bytes = ip_u32.to_ne_bytes();
        let value_bytes = [action as u8];
        
        self.rules.update(&key_bytes, &value_bytes, libbpf_rs::MapFlags::ANY)?;
            
        log::info!("Rule updated successfully for IP {}", ip);
        Ok(())
    }

    pub fn remove_rule(&self, ip: Ipv4Addr) -> Result<(), libbpf_rs::Error> {
        log::info!("Removing rule for IP {}", ip);
        
        let ip_bytes = ip.octets();
        let ip_u32 = u32::from_be_bytes(ip_bytes);
        
        let key_bytes = ip_u32.to_ne_bytes();
        
        self.rules.delete(&key_bytes)?;
            
        log::info!("Rule removed successfully for IP {}", ip);
        Ok(())
    }

    pub fn get_all_rules(&self) -> Result<Vec<Rule>, libbpf_rs::Error> {
        let mut rules = Vec::new();
        
        // Iterate through all entries in the map
        for key in self.rules.keys() {
            if let Some(value) = self.rules.lookup(&key, libbpf_rs::MapFlags::ANY)? {
                // Convert key (4 bytes) to IP address
                if key.len() >= 4 {
                    let ip_u32 = u32::from_ne_bytes([key[0], key[1], key[2], key[3]]);
                    let ip = Ipv4Addr::from(u32::from_be_bytes(ip_u32.to_be_bytes()));
                    
                    // Convert value (1 byte) to action
                    if !value.is_empty() {
                        let action = if value[0] == 0 {
                            Action::Drop
                        } else {
                            Action::Allow
                        };
                        
                        rules.push(Rule { ip, action });
                    }
                }
            }
        }
        
        log::info!("Loaded {} existing rules from eBPF map", rules.len());
        Ok(rules)
    }
    
    // Metadata map operations
    pub fn add_rule_metadata(&self, name: &str, ip: Ipv4Addr, action: u8, description: Option<&str>) -> Result<(), libbpf_rs::Error> {
        let metadata = RuleMetadata::new(ip, action, name, description);
        let metadata_bytes = unsafe {
            std::slice::from_raw_parts(
                &metadata as *const RuleMetadata as *const u8,
                std::mem::size_of::<RuleMetadata>()
            )
        };
        
        let mut key_bytes = [0u8; 64];
        let name_len = name.len().min(63);
        key_bytes[..name_len].copy_from_slice(&name.as_bytes()[..name_len]);
        
        self.metadata.update(&key_bytes, metadata_bytes, libbpf_rs::MapFlags::ANY)?;
        log::info!("Added metadata for rule '{}'", name);
        Ok(())
    }
    
    pub fn get_rule_metadata(&self, name: &str) -> Result<Option<RuleMetadata>, libbpf_rs::Error> {
        let mut key_bytes = [0u8; 64];
        let name_len = name.len().min(63);
        key_bytes[..name_len].copy_from_slice(&name.as_bytes()[..name_len]);
        
        if let Some(value) = self.metadata.lookup(&key_bytes, libbpf_rs::MapFlags::ANY)? {
            if value.len() >= std::mem::size_of::<RuleMetadata>() {
                let metadata = unsafe {
                    std::ptr::read(value.as_ptr() as *const RuleMetadata)
                };
                return Ok(Some(metadata));
            }
        }
        Ok(None)
    }
    
    pub fn delete_rule_metadata(&self, name: &str) -> Result<(), libbpf_rs::Error> {
        let mut key_bytes = [0u8; 64];
        let name_len = name.len().min(63);
        key_bytes[..name_len].copy_from_slice(&name.as_bytes()[..name_len]);
        
        self.metadata.delete(&key_bytes)?;
        log::info!("Deleted metadata for rule '{}'", name);
        Ok(())
    }
    
    pub fn list_all_metadata(&self) -> Result<Vec<PolicyRule>, libbpf_rs::Error> {
        let mut rules = Vec::new();
        
        for key in self.metadata.keys() {
            if let Some(value) = self.metadata.lookup(&key, libbpf_rs::MapFlags::ANY)? {
                if value.len() >= std::mem::size_of::<RuleMetadata>() {
                    let metadata = unsafe {
                        std::ptr::read(value.as_ptr() as *const RuleMetadata)
                    };
                    rules.push(metadata.to_policy_rule());
                }
            }
        }
        
        Ok(rules)
    }
}
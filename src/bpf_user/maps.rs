use libbpf_rs::{Map, MapCore};
use std::net::Ipv4Addr;
use crate::models::rule::{Action, Rule};

pub struct BpfMaps<'a> {
    pub rules: Map<'a>,
    pub log_events: Map<'a>,
}

impl<'a> BpfMaps<'a> {
    pub fn new(obj: &'a libbpf_rs::Object) -> Self {
        let mut maps = obj.maps();
        let rules = maps.next().expect("rules_map not found");
        let log_events = maps.next().expect("log_events_map not found");
        
        BpfMaps { rules, log_events }
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
}
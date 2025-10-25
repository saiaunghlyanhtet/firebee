use libbpf_rs::{Map, MapCore};
use std::net::Ipv4Addr;

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
}
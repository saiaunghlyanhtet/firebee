use crate::ui::app::Command;
use crate::bpf_user::{loader::BpfLoader, maps::BpfMaps};
use crate::models::rule::Rule;
use tokio::sync::mpsc;
use libbpf_rs::{RingBufferBuilder, Link};
use std::net::Ipv4Addr;

pub struct BpfHandler {
    bpf_object: Box<libbpf_rs::Object>,  
    maps: BpfMaps<'static>,
    cmd_rx: mpsc::Receiver<Command>,
    log_tx: mpsc::Sender<String>,
    links: Vec<Link>, 
}

impl BpfHandler {
    pub fn new(loader: BpfLoader, cmd_rx: mpsc::Receiver<Command>, log_tx: mpsc::Sender<String>) -> Self {
        let bpf_object = Box::new(loader.bpf_object);
        
        let obj_ref = Box::leak(Box::new(&*bpf_object));
        let maps = unsafe { std::mem::transmute::<BpfMaps<'_>, BpfMaps<'static>>(BpfMaps::new(*obj_ref)) };
        
        let links = loader.links;
        
        BpfHandler { bpf_object, maps, cmd_rx, log_tx, links }
    }

    pub fn get_all_rules(&self) -> Result<Vec<Rule>, libbpf_rs::Error> {
        self.maps.get_all_rules()
    }

    pub async fn run(&mut self) {
        let mut rb = RingBufferBuilder::new();
        let log_tx = self.log_tx.clone();
        
        rb.add(&self.maps.log_events, move |data| {
            if data.len() >= 8 {
                let src_ip = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                let action = data[4]; 
                let ip = Ipv4Addr::from(src_ip);
                let msg = format!(
                    "Packet from {}: {}",
                    ip,
                    if action == 0 { "DROPPED" } else { "PASSED" }
                );
                
                if let Ok(()) = log_tx.try_send(msg) {
                    // Message sent successfully
                }
            }
            0 
        })
        .expect("Failed to create ring buffer");
        let rb = rb.build().expect("Failed to build ring buffer");

        loop {
            // Process commands
            while let Ok(cmd) = self.cmd_rx.try_recv() {
                match cmd {
                    Command::AddRule(rule) => {
                        let action = match rule.action {
                            crate::models::rule::Action::Allow => 1,
                            crate::models::rule::Action::Drop => 0,
                        };
                        if let Err(e) = self.maps.update_rule(rule.ip, action) {
                            log::error!("Failed to update rule: {}", e);
                        }
                    }
                    Command::RemoveRule(ip) => {
                        if let Err(e) = self.maps.remove_rule(ip) {
                            log::error!("Failed to remove rule: {}", e);
                        }
                    }
                }
            }

            // Poll ring buffer - returns number of records processed
            let _ = rb.poll(std::time::Duration::from_millis(100));

            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }
}

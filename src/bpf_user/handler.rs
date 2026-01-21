use crate::bpf_user::{loader::BpfLoader, maps::BpfMaps};
use crate::models::rule::Rule;
use crate::ui::app::Command;
use libbpf_rs::{Link, RingBufferBuilder};
use std::net::Ipv4Addr;
use tokio::sync::mpsc;

#[allow(dead_code)]
pub struct BpfHandler {
    bpf_object: Option<Box<libbpf_rs::Object>>,
    maps: Option<BpfMaps<'static>>,
    cmd_rx: mpsc::Receiver<Command>,
    log_tx: mpsc::Sender<String>,
    links: Vec<Link>,
    interface: String,
}

impl BpfHandler {
    #[allow(dead_code)]
    pub fn new(
        loader: BpfLoader,
        cmd_rx: mpsc::Receiver<Command>,
        log_tx: mpsc::Sender<String>,
    ) -> Self {
        let bpf_object = Box::new(loader.bpf_object);
        let interface = loader.interface;
        let links = loader.links;

        // SAFETY: the boxed object lives for the lifetime of the handler. We ensure
        // maps are dropped before the boxed object by storing them in Options and
        // taking them during unload/Drop.
        let obj_ref: &'static libbpf_rs::Object = unsafe {
            std::mem::transmute::<&libbpf_rs::Object, &'static libbpf_rs::Object>(&*bpf_object)
        };
        let maps = BpfMaps::new(obj_ref);

        BpfHandler {
            bpf_object: Some(bpf_object),
            maps: Some(maps),
            cmd_rx,
            log_tx,
            links,
            interface,
        }
    }

    #[allow(dead_code)]
    pub fn get_all_rules(&self) -> Result<Vec<Rule>, libbpf_rs::Error> {
        if let Some(maps) = &self.maps {
            maps.get_all_rules()
        } else {
            Ok(Vec::new())
        }
    }

    #[allow(dead_code)]
    pub async fn run(&mut self) {
        let mut rb_builder = RingBufferBuilder::new();
        let log_tx = self.log_tx.clone();

        let log_map = self
            .maps
            .as_ref()
            .expect("BPF maps missing before handler run");

        rb_builder
            .add(&log_map.log_events, move |data| {
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

        let rb = rb_builder.build().expect("Failed to build ring buffer");
        let mut should_unload = false;

        loop {
            while let Ok(cmd) = self.cmd_rx.try_recv() {
                match cmd {
                    Command::AddRule(rule) => {
                        let action = match rule.action {
                            crate::models::rule::Action::Allow => 1,
                            crate::models::rule::Action::Drop => 0,
                        };
                        if let Some(maps) = self.maps.as_ref() {
                            if let Err(e) = maps.update_rule(&rule, action) {
                                log::error!("Failed to update rule: {}", e);
                            }
                        } else {
                            log::warn!("AddRule received after maps were released");
                        }
                    }
                    Command::RemoveRule(ip) => {
                        if let Some(maps) = self.maps.as_ref() {
                            let mut found = false;

                            match maps.list_all_metadata() {
                                Ok(policy_rules) => {
                                    for policy_rule in policy_rules {
                                        if let Ok(rule) = policy_rule.to_rule() {
                                            if rule.ip == ip {
                                                if let Err(e) = maps.remove_rule(&rule) {
                                                    log::error!(
                                                        "Failed to remove rule from rules map: {}",
                                                        e
                                                    );
                                                } else if let Err(e) =
                                                    maps.delete_rule_metadata(&policy_rule.name)
                                                {
                                                    log::error!(
                                                        "Failed to delete rule metadata: {}",
                                                        e
                                                    );
                                                } else {
                                                    log::info!(
                                                        "Successfully removed rule '{}' for IP {}",
                                                        policy_rule.name,
                                                        ip
                                                    );
                                                    found = true;
                                                }
                                                break;
                                            }
                                        }
                                    }

                                    if !found {
                                        log::warn!("No rule found with IP {} in metadata", ip);
                                    }
                                }
                                Err(e) => {
                                    log::error!("Failed to list metadata for removal: {}", e);
                                }
                            }
                        } else {
                            log::warn!("RemoveRule received after maps were released");
                        }
                    }
                    Command::Unload => {
                        log::info!("Received unload command, beginning cleanup...");
                        drop(std::mem::take(&mut self.links));
                        should_unload = true;
                        break;
                    }
                }
            }

            if should_unload {
                break;
            }

            let _ = rb.poll(std::time::Duration::from_millis(100));

            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        drop(rb);

        if should_unload {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;

            if let Some(_maps) = self.maps.take() {}
            if let Some(obj) = self.bpf_object.take() {
                drop(obj);
            }

            if let Err(e) = BpfLoader::unload(&self.interface) {
                log::error!("Failed to unload BPF resources: {}", e);
            }
        }
    }
}

impl Drop for BpfHandler {
    fn drop(&mut self) {
        if let Some(_maps) = self.maps.take() {}
        if let Some(obj) = self.bpf_object.take() {
            drop(obj);
        }
        if !self.links.is_empty() {
            drop(std::mem::take(&mut self.links));
        }
    }
}

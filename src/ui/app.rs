use crate::models::rule::{Action, Rule};
use crate::policy::PolicyRule;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use tokio::sync::mpsc;

pub enum Command {
    AddRule(Rule),
    RemoveRule(Ipv4Addr),
    Unload,
}

pub struct App {
    pub rules: Vec<PolicyRule>,
    pub logs: Vec<String>,
    pub input: String,
    pub input_mode: bool,
    pub confirm_unload: bool,
    pub unload_requested: bool,
    pub rule_stats: HashMap<String, (u64, u64)>, // name -> (packets, bytes)
    cmd_tx: mpsc::Sender<Command>,
    log_rx: mpsc::Receiver<String>,
}

impl App {
    pub fn new(cmd_tx: mpsc::Sender<Command>, log_rx: mpsc::Receiver<String>, initial_rules: Vec<PolicyRule>) -> Self {
        Self {
            rules: initial_rules,
            logs: vec![],
            input: String::new(),
            input_mode: false,
            confirm_unload: false,
            unload_requested: false,
            rule_stats: HashMap::new(),
            cmd_tx,
            log_rx,
        }
    }
    
    pub fn update_stats(&mut self, stats: HashMap<String, (u64, u64)>) {
        self.rule_stats = stats;
    }

    pub async fn update(&mut self) {
        while let Ok(log) = self.log_rx.try_recv() {
            self.logs.push(log);
            if self.logs.len() > 100 {
                self.logs.remove(0);
            }
        }
    }

    pub async fn add_rule(&mut self, ip: &str, action: Action) -> bool {
        if let Ok(ip_addr) = ip.parse::<Ipv4Addr>() {
            let rule = Rule {
                ip: ip_addr,
                subnet_mask: None,
                action: action.clone(),
                protocol: crate::models::rule::Protocol::Any,
                src_port: None,
                dst_port: None,
            };
            // Create a PolicyRule for display
            let policy_rule = PolicyRule {
                name: format!("rule_{}", ip),
                ip: ip.to_string(),
                action: match action {
                    Action::Allow => "allow".to_string(),
                    Action::Drop => "drop".to_string(),
                },
                description: None,
                protocol: "any".to_string(),
                src_port: None,
                dst_port: None,
            };
            self.rules.push(policy_rule);
            self.cmd_tx.send(Command::AddRule(rule)).await.is_ok()
        } else {
            false
        }
    }

    pub async fn remove_rule(&mut self, ip: Ipv4Addr) -> bool {
        self.rules.retain(|r| r.ip != ip.to_string());
        self.cmd_tx.send(Command::RemoveRule(ip)).await.is_ok()
    }

    pub async fn unload(&mut self) -> bool {
        match self.cmd_tx.send(Command::Unload).await {
            Ok(_) => {
                self.unload_requested = true;
                true
            }
            Err(_) => false,
        }
    }
}

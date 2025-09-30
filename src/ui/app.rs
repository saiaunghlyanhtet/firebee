use crate::models::rule::{Action, Rule};
use std::net::Ipv4Addr;
use tokio::sync::mpsc;

pub enum Command {
    AddRule(Rule),
    RemoveRule(Ipv4Addr),
}

pub struct App {
    pub rules: Vec<Rule>,
    pub logs: Vec<String>,
    pub input: String,
    pub input_mode: bool,
    cmd_tx: mpsc::Sender<Command>,
    log_rx: mpsc::Receiver<String>,
}

impl App {
    pub fn new(cmd_tx: mpsc::Sender<Command>, log_rx: mpsc::Receiver<String>) -> Self {
        Self {
            rules: vec![],
            logs: vec![],
            input: String::new(),
            input_mode: false,
            cmd_tx,
            log_rx,
        }
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
                action,
            };
            self.rules.push(rule.clone());
            self.cmd_tx.send(Command::AddRule(rule)).await.is_ok()
        } else {
            false
        }
    }

    pub async fn remove_rule(&mut self, ip: Ipv4Addr) -> bool {
        self.rules.retain(|r| r.ip != ip);
        self.cmd_tx.send(Command::RemoveRule(ip)).await.is_ok()
    }
}

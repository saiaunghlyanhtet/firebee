use crate::policy::PolicyRule;
use std::collections::HashMap;
use tokio::sync::mpsc;

pub struct App {
    pub rules: Vec<PolicyRule>,
    pub logs: Vec<String>,
    pub rule_stats: HashMap<String, (u64, u64)>,
    log_rx: mpsc::Receiver<String>,
}

impl App {
    pub fn new(log_rx: mpsc::Receiver<String>, initial_rules: Vec<PolicyRule>) -> Self {
        Self {
            rules: initial_rules,
            logs: vec![],
            rule_stats: HashMap::new(),
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
}

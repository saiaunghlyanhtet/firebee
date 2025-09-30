use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

#[derive(Clone, Serialize, Deserialize)]
pub enum Action {
    Allow,
    Drop,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Rule {
    pub ip: Ipv4Addr,
    pub action: Action,
}

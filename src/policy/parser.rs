use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use crate::models::rule::{Action, Rule};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub name: String,
    pub ip: String,
    pub action: String,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PolicyFile {
    pub rules: Vec<PolicyRule>,
}

impl PolicyRule {
    pub fn to_rule(&self) -> Result<Rule> {
        let ip: Ipv4Addr = self.ip.parse()
            .with_context(|| format!("Invalid IP address '{}' in rule '{}'", self.ip, self.name))?;
        
        let action = match self.action.to_lowercase().as_str() {
            "allow" | "pass" | "accept" => Action::Allow,
            "drop" | "deny" | "block" => Action::Drop,
            _ => anyhow::bail!("Invalid action '{}' in rule '{}'. Must be 'allow' or 'drop'", self.action, self.name),
        };

        Ok(Rule { ip, action })
    }
}

pub fn parse_policy_file<P: AsRef<Path>>(path: P) -> Result<PolicyFile> {
    let path = path.as_ref();
    let content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read policy file: {}", path.display()))?;
    
    // Detect format based on file extension
    let extension = path.extension()
        .and_then(|e| e.to_str())
        .unwrap_or("yaml"); // Default to YAML
    
    let policy: PolicyFile = match extension {
        "json" => serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse policy file as JSON: {}", path.display()))?,
        "yaml" | "yml" | _ => serde_yaml::from_str(&content)
            .with_context(|| format!("Failed to parse policy file as YAML: {}", path.display()))?,
    };
    
    Ok(policy)
}

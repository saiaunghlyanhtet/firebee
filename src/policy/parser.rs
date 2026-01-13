use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use crate::models::rule::{Action, Direction, Protocol, Rule};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub name: String,
    pub ip: String,
    pub action: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default = "default_protocol")]
    pub protocol: String,
    #[serde(default = "default_direction")]
    pub direction: String,
    #[serde(default)]
    pub src_port: Option<u16>,
    #[serde(default)]
    pub dst_port: Option<u16>,
}

fn default_protocol() -> String {
    "any".to_string()
}

fn default_direction() -> String {
    "ingress".to_string()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PolicyFile {
    pub rules: Vec<PolicyRule>,
}

impl PolicyRule {
    pub fn to_rule(&self) -> Result<Rule> {
        // Parse IP with optional CIDR notation
        let (ip, subnet_mask) = if self.ip.contains('/') {
            let parts: Vec<&str> = self.ip.split('/').collect();
            if parts.len() != 2 {
                anyhow::bail!("Invalid CIDR notation '{}' in rule '{}'", self.ip, self.name);
            }
            let ip: Ipv4Addr = parts[0].parse()
                .with_context(|| format!("Invalid IP address '{}' in rule '{}'", parts[0], self.name))?;
            let prefix: u8 = parts[1].parse()
                .with_context(|| format!("Invalid CIDR prefix '{}' in rule '{}'", parts[1], self.name))?;
            if prefix > 32 {
                anyhow::bail!("CIDR prefix must be <= 32, got {} in rule '{}'", prefix, self.name);
            }
            (ip, Some(prefix))
        } else {
            let ip: Ipv4Addr = self.ip.parse()
                .with_context(|| format!("Invalid IP address '{}' in rule '{}'", self.ip, self.name))?;
            (ip, None)
        };
        
        let action = match self.action.to_lowercase().as_str() {
            "allow" | "pass" | "accept" => Action::Allow,
            "drop" | "deny" | "block" => Action::Drop,
            _ => anyhow::bail!("Invalid action '{}' in rule '{}'. Must be 'allow' or 'drop'", self.action, self.name),
        };

        let protocol = match self.protocol.to_lowercase().as_str() {
            "tcp" => Protocol::TCP,
            "udp" => Protocol::UDP,
            "icmp" => Protocol::ICMP,
            "any" | "" => Protocol::Any,
            _ => anyhow::bail!("Invalid protocol '{}' in rule '{}'. Must be tcp, udp, icmp, or any", self.protocol, self.name),
        };

        let direction = match self.direction.to_lowercase().as_str() {
            "ingress" | "in" | "input" => Direction::Ingress,
            "egress" | "out" | "output" => Direction::Egress,
            "both" | "any" => Direction::Both,
            _ => anyhow::bail!("Invalid direction '{}' in rule '{}'. Must be ingress, egress, or both", self.direction, self.name),
        };

        Ok(Rule { 
            ip, 
            subnet_mask,
            action,
            protocol,
            direction,
            src_port: self.src_port,
            dst_port: self.dst_port,
        })
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

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_rule(name: &str, ip: &str, action: &str, protocol: &str) -> PolicyRule {
        PolicyRule {
            name: name.to_string(),
            ip: ip.to_string(),
            action: action.to_string(),
            description: None,
            protocol: protocol.to_string(),
            src_port: None,
            dst_port: None,
            direction: "ingress".to_string(),
        }
    }

    #[test]
    fn test_valid_ipv4_parsing() {
        let rule = create_test_rule("test", "192.168.1.1", "allow", "any");
        let result = rule.to_rule();
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.ip.to_string(), "192.168.1.1");
        assert_eq!(parsed.subnet_mask, None);
    }

    #[test]
    fn test_valid_cidr_notation() {
        let rule = create_test_rule("test", "192.168.1.0/24", "allow", "any");
        let result = rule.to_rule();
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.ip.to_string(), "192.168.1.0");
        assert_eq!(parsed.subnet_mask, Some(24));
    }

    #[test]
    fn test_valid_cidr_prefix_0() {
        let rule = create_test_rule("test", "0.0.0.0/0", "allow", "any");
        let result = rule.to_rule();
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.subnet_mask, Some(0));
    }

    #[test]
    fn test_valid_cidr_prefix_32() {
        let rule = create_test_rule("test", "192.168.1.1/32", "allow", "any");
        let result = rule.to_rule();
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.subnet_mask, Some(32));
    }

    #[test]
    fn test_invalid_cidr_prefix_too_large() {
        let rule = create_test_rule("test", "192.168.1.0/33", "allow", "any");
        let result = rule.to_rule();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("CIDR prefix must be <= 32"));
    }

    #[test]
    fn test_invalid_cidr_notation_multiple_slashes() {
        let rule = create_test_rule("test", "192.168.1.0/24/16", "allow", "any");
        let result = rule.to_rule();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Invalid CIDR notation"));
    }

    #[test]
    fn test_invalid_cidr_notation_non_numeric_prefix() {
        let rule = create_test_rule("test", "192.168.1.0/abc", "allow", "any");
        let result = rule.to_rule();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Invalid CIDR prefix"));
    }

    #[test]
    fn test_invalid_ip_address() {
        let rule = create_test_rule("test", "invalid.ip.address", "allow", "any");
        let result = rule.to_rule();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Invalid IP address"));
    }

    #[test]
    fn test_invalid_ip_in_cidr() {
        let rule = create_test_rule("test", "invalid.ip/24", "allow", "any");
        let result = rule.to_rule();
        assert!(result.is_err());
    }

    #[test]
    fn test_protocol_tcp() {
        let rule = create_test_rule("test", "192.168.1.1", "allow", "tcp");
        let result = rule.to_rule();
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert!(matches!(parsed.protocol, Protocol::TCP));
    }

    #[test]
    fn test_protocol_udp() {
        let rule = create_test_rule("test", "192.168.1.1", "allow", "udp");
        let result = rule.to_rule();
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert!(matches!(parsed.protocol, Protocol::UDP));
    }

    #[test]
    fn test_protocol_icmp() {
        let rule = create_test_rule("test", "192.168.1.1", "allow", "icmp");
        let result = rule.to_rule();
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert!(matches!(parsed.protocol, Protocol::ICMP));
    }

    #[test]
    fn test_protocol_any() {
        let rule = create_test_rule("test", "192.168.1.1", "allow", "any");
        let result = rule.to_rule();
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert!(matches!(parsed.protocol, Protocol::Any));
    }

    #[test]
    fn test_protocol_empty_defaults_to_any() {
        let rule = create_test_rule("test", "192.168.1.1", "allow", "");
        let result = rule.to_rule();
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert!(matches!(parsed.protocol, Protocol::Any));
    }

    #[test]
    fn test_protocol_case_insensitive() {
        let test_cases = vec!["TCP", "Tcp", "tCp", "UDP", "Udp", "ICMP", "Icmp", "ANY", "Any"];
        for protocol in test_cases {
            let rule = create_test_rule("test", "192.168.1.1", "allow", protocol);
            let result = rule.to_rule();
            assert!(result.is_ok(), "Protocol '{}' should be valid", protocol);
        }
    }

    #[test]
    fn test_invalid_protocol() {
        let rule = create_test_rule("test", "192.168.1.1", "allow", "invalid");
        let result = rule.to_rule();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Invalid protocol"));
    }

    #[test]
    fn test_action_allow_variants() {
        let variants = vec!["allow", "pass", "accept", "ALLOW", "Pass", "Accept"];
        for action in variants {
            let rule = create_test_rule("test", "192.168.1.1", action, "any");
            let result = rule.to_rule();
            assert!(result.is_ok(), "Action '{}' should be valid", action);
            let parsed = result.unwrap();
            assert!(matches!(parsed.action, Action::Allow));
        }
    }

    #[test]
    fn test_action_drop_variants() {
        let variants = vec!["drop", "deny", "block", "DROP", "Deny", "Block"];
        for action in variants {
            let rule = create_test_rule("test", "192.168.1.1", action, "any");
            let result = rule.to_rule();
            assert!(result.is_ok(), "Action '{}' should be valid", action);
            let parsed = result.unwrap();
            assert!(matches!(parsed.action, Action::Drop));
        }
    }

    #[test]
    fn test_invalid_action() {
        let rule = create_test_rule("test", "192.168.1.1", "invalid", "any");
        let result = rule.to_rule();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Invalid action"));
    }

    #[test]
    fn test_ports_with_protocol() {
        let mut rule = create_test_rule("test", "192.168.1.1", "allow", "tcp");
        rule.src_port = Some(8080);
        rule.dst_port = Some(80);
        let result = rule.to_rule();
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.src_port, Some(8080));
        assert_eq!(parsed.dst_port, Some(80));
    }

    #[test]
    fn test_valid_port_boundaries() {
        let mut rule = create_test_rule("test", "192.168.1.1", "allow", "tcp");
        
        // Test minimum port
        rule.src_port = Some(0);
        assert!(rule.to_rule().is_ok());
        
        // Test maximum port
        rule.src_port = Some(65535);
        assert!(rule.to_rule().is_ok());
    }

    #[test]
    fn test_complex_rule_with_all_fields() {
        let rule = PolicyRule {
            name: "complex_rule".to_string(),
            ip: "10.0.0.0/8".to_string(),
            action: "drop".to_string(),
            description: Some("Block entire 10.x network".to_string()),
            protocol: "tcp".to_string(),
            src_port: Some(443),
            dst_port: Some(80),
            direction: "ingress".to_string(),
        };
        
        let result = rule.to_rule();
        assert!(result.is_ok());
        let parsed = result.unwrap();
        
        assert_eq!(parsed.ip.to_string(), "10.0.0.0");
        assert_eq!(parsed.subnet_mask, Some(8));
        assert!(matches!(parsed.action, Action::Drop));
        assert!(matches!(parsed.protocol, Protocol::TCP));
        assert_eq!(parsed.src_port, Some(443));
        assert_eq!(parsed.dst_port, Some(80));
    }
}

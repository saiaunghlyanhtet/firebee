use super::PolicyFile;
use anyhow::{Context, Result};
use std::collections::{HashMap, HashSet};

pub fn validate_policy(policy: &PolicyFile) -> Result<()> {
    if policy.rules.is_empty() {
        anyhow::bail!("Policy file must contain at least one rule");
    }

    let mut seen_names = HashSet::new();
    let mut seen_ips = HashMap::new();

    for (idx, rule) in policy.rules.iter().enumerate() {
        let rule_pos = format!("rule #{} ('{}')", idx + 1, rule.name);

        if rule.name.is_empty() {
            anyhow::bail!("{}: rule name cannot be empty", rule_pos);
        }

        if !seen_names.insert(rule.name.clone()) {
            anyhow::bail!("{}: duplicate rule name '{}'", rule_pos, rule.name);
        }

        let _ = rule
            .to_rule()
            .with_context(|| format!("{}: validation failed", rule_pos))?;

        if let Some(prev_idx) = seen_ips.insert(rule.ip.clone(), idx) {
            log::warn!(
                "Warning: IP {} appears in multiple rules: '{}' and '{}'",
                rule.ip,
                policy.rules[prev_idx].name,
                rule.name
            );
        }

        let action_lower = rule.action.to_lowercase();
        if !["allow", "pass", "accept", "drop", "deny", "block"].contains(&action_lower.as_str()) {
            anyhow::bail!(
                "{}: invalid action '{}'. Must be one of: allow, pass, accept, drop, deny, block",
                rule_pos,
                rule.action
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::PolicyRule;

    #[test]
    fn test_empty_rules() {
        let policy = PolicyFile { rules: vec![] };
        assert!(validate_policy(&policy).is_err());
    }

    #[test]
    fn test_duplicate_names() {
        let policy = PolicyFile {
            rules: vec![
                PolicyRule {
                    name: "rule1".to_string(),
                    ip: "192.168.1.1".to_string(),
                    action: "drop".to_string(),
                    description: None,
                    protocol: "any".to_string(),
                    src_port: None,
                    dst_port: None,
                    direction: "ingress".to_string(),
                },
                PolicyRule {
                    name: "rule1".to_string(),
                    ip: "192.168.1.2".to_string(),
                    action: "allow".to_string(),
                    description: None,
                    protocol: "any".to_string(),
                    src_port: None,
                    dst_port: None,
                    direction: "ingress".to_string(),
                },
            ],
        };
        assert!(validate_policy(&policy).is_err());
    }

    #[test]
    fn test_invalid_ip() {
        let policy = PolicyFile {
            rules: vec![PolicyRule {
                name: "rule1".to_string(),
                ip: "invalid.ip".to_string(),
                action: "drop".to_string(),
                description: None,
                protocol: "any".to_string(),
                src_port: None,
                dst_port: None,
                direction: "ingress".to_string(),
            }],
        };
        assert!(validate_policy(&policy).is_err());
    }

    #[test]
    fn test_valid_policy() {
        let policy = PolicyFile {
            rules: vec![
                PolicyRule {
                    name: "rule1".to_string(),
                    ip: "192.168.1.1".to_string(),
                    action: "drop".to_string(),
                    description: Some("Block suspicious IP".to_string()),
                    protocol: "any".to_string(),
                    src_port: None,
                    dst_port: None,
                    direction: "ingress".to_string(),
                },
                PolicyRule {
                    name: "rule2".to_string(),
                    ip: "10.0.0.1".to_string(),
                    action: "allow".to_string(),
                    description: None,
                    protocol: "tcp".to_string(),
                    src_port: None,
                    dst_port: Some(80),
                    direction: "ingress".to_string(),
                },
            ],
        };
        assert!(validate_policy(&policy).is_ok());
    }

    #[test]
    fn test_empty_rule_name() {
        let policy = PolicyFile {
            rules: vec![PolicyRule {
                name: "".to_string(),
                ip: "192.168.1.1".to_string(),
                action: "drop".to_string(),
                description: None,
                protocol: "any".to_string(),
                src_port: None,
                dst_port: None,
                direction: "ingress".to_string(),
            }],
        };
        let result = validate_policy(&policy);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("name cannot be empty"));
    }

    #[test]
    fn test_invalid_action_check() {
        let policy = PolicyFile {
            rules: vec![PolicyRule {
                name: "test".to_string(),
                ip: "192.168.1.1".to_string(),
                action: "reject".to_string(),
                description: None,
                protocol: "any".to_string(),
                src_port: None,
                dst_port: None,
                direction: "ingress".to_string(),
            }],
        };
        let result = validate_policy(&policy);
        assert!(
            result.is_err(),
            "Invalid action 'reject' should cause validation to fail"
        );
    }

    #[test]
    fn test_valid_action_variants() {
        let valid_actions = vec![
            "allow", "pass", "accept", "drop", "deny", "block", "ALLOW", "Pass", "ACCEPT", "DROP",
            "Deny", "BLOCK",
        ];

        for action in valid_actions {
            let policy = PolicyFile {
                rules: vec![PolicyRule {
                    name: "test".to_string(),
                    ip: "192.168.1.1".to_string(),
                    action: action.to_string(),
                    description: None,
                    protocol: "any".to_string(),
                    src_port: None,
                    dst_port: None,
                    direction: "ingress".to_string(),
                }],
            };
            assert!(
                validate_policy(&policy).is_ok(),
                "Action '{}' should be valid",
                action
            );
        }
    }

    #[test]
    fn test_multiple_rules_different_ips() {
        let policy = PolicyFile {
            rules: vec![
                PolicyRule {
                    name: "rule1".to_string(),
                    ip: "192.168.1.1".to_string(),
                    action: "drop".to_string(),
                    description: None,
                    protocol: "tcp".to_string(),
                    src_port: None,
                    dst_port: Some(80),
                    direction: "ingress".to_string(),
                },
                PolicyRule {
                    name: "rule2".to_string(),
                    ip: "10.0.0.1".to_string(),
                    action: "allow".to_string(),
                    description: None,
                    protocol: "udp".to_string(),
                    src_port: None,
                    dst_port: Some(53),
                    direction: "egress".to_string(),
                },
                PolicyRule {
                    name: "rule3".to_string(),
                    ip: "172.16.0.0/12".to_string(),
                    action: "block".to_string(),
                    description: Some("Block private network".to_string()),
                    protocol: "any".to_string(),
                    src_port: None,
                    dst_port: None,
                    direction: "both".to_string(),
                },
            ],
        };
        assert!(validate_policy(&policy).is_ok());
    }

    #[test]
    fn test_rule_with_all_port_combinations() {
        let test_cases = vec![
            (None, None),
            (Some(80), None),
            (None, Some(443)),
            (Some(8080), Some(443)),
        ];

        for (src_port, dst_port) in test_cases {
            let policy = PolicyFile {
                rules: vec![PolicyRule {
                    name: format!("rule_{:?}_{:?}", src_port, dst_port),
                    ip: "192.168.1.1".to_string(),
                    action: "allow".to_string(),
                    description: None,
                    protocol: "tcp".to_string(),
                    src_port,
                    dst_port,
                    direction: "ingress".to_string(),
                }],
            };
            assert!(validate_policy(&policy).is_ok());
        }
    }

    #[test]
    fn test_all_direction_values() {
        let directions = vec!["ingress", "egress", "both"];

        for direction in directions {
            let policy = PolicyFile {
                rules: vec![PolicyRule {
                    name: format!("test_{}", direction),
                    ip: "192.168.1.1".to_string(),
                    action: "allow".to_string(),
                    description: None,
                    protocol: "any".to_string(),
                    src_port: None,
                    dst_port: None,
                    direction: direction.to_string(),
                }],
            };
            assert!(validate_policy(&policy).is_ok());
        }
    }

    #[test]
    fn test_cidr_validation() {
        let valid_cidrs = vec![
            "192.168.1.0/24",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "0.0.0.0/0",
            "192.168.1.1/32",
        ];

        for cidr in valid_cidrs {
            let policy = PolicyFile {
                rules: vec![PolicyRule {
                    name: format!("test_{}", cidr.replace('/', "_")),
                    ip: cidr.to_string(),
                    action: "drop".to_string(),
                    description: None,
                    protocol: "any".to_string(),
                    src_port: None,
                    dst_port: None,
                    direction: "ingress".to_string(),
                }],
            };
            assert!(
                validate_policy(&policy).is_ok(),
                "CIDR {} should be valid",
                cidr
            );
        }
    }

    #[test]
    fn test_protocol_variations() {
        let protocols = vec!["tcp", "udp", "icmp", "any", "TCP", "UDP", "ICMP", "ANY"];

        for protocol in protocols {
            let policy = PolicyFile {
                rules: vec![PolicyRule {
                    name: format!("test_{}", protocol),
                    ip: "192.168.1.1".to_string(),
                    action: "allow".to_string(),
                    description: None,
                    protocol: protocol.to_string(),
                    src_port: None,
                    dst_port: None,
                    direction: "ingress".to_string(),
                }],
            };
            assert!(validate_policy(&policy).is_ok());
        }
    }
}

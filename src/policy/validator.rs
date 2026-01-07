use anyhow::{Context, Result};
use std::collections::{HashMap, HashSet};
use super::PolicyFile;

pub fn validate_policy(policy: &PolicyFile) -> Result<()> {
    // Check if we have any rules
    if policy.rules.is_empty() {
        anyhow::bail!("Policy file must contain at least one rule");
    }

    let mut seen_names = HashSet::new();
    let mut seen_ips = HashMap::new();

    for (idx, rule) in policy.rules.iter().enumerate() {
        let rule_pos = format!("rule #{} ('{}')", idx + 1, rule.name);

        // Validate rule name is not empty
        if rule.name.is_empty() {
            anyhow::bail!("{}: rule name cannot be empty", rule_pos);
        }

        // Check for duplicate rule names
        if !seen_names.insert(rule.name.clone()) {
            anyhow::bail!("{}: duplicate rule name '{}'", rule_pos, rule.name);
        }

        // Validate IP address format by attempting to parse it
        let _ = rule.to_rule()
            .with_context(|| format!("{}: validation failed", rule_pos))?;

        // Check for duplicate IPs (warning, not error)
        if let Some(prev_idx) = seen_ips.insert(rule.ip.clone(), idx) {
            log::warn!(
                "Warning: IP {} appears in multiple rules: '{}' and '{}'",
                rule.ip,
                policy.rules[prev_idx].name,
                rule.name
            );
        }

        // Validate action
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
        let policy = PolicyFile {
            rules: vec![],
        };
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
                },
                PolicyRule {
                    name: "rule1".to_string(),
                    ip: "192.168.1.2".to_string(),
                    action: "allow".to_string(),
                    description: None,
                },
            ],
        };
        assert!(validate_policy(&policy).is_err());
    }

    #[test]
    fn test_invalid_ip() {
        let policy = PolicyFile {
            rules: vec![
                PolicyRule {
                    name: "rule1".to_string(),
                    ip: "invalid.ip".to_string(),
                    action: "drop".to_string(),
                    description: None,
                },
            ],
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
                },
                PolicyRule {
                    name: "rule2".to_string(),
                    ip: "10.0.0.1".to_string(),
                    action: "allow".to_string(),
                    description: None,
                },
            ],
        };
        assert!(validate_policy(&policy).is_ok());
    }
}

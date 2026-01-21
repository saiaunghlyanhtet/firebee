use crate::bpf_user::maps::BpfMaps;
use crate::policy::PolicyRule;
use anyhow::{Context, Result};

pub struct RulesState;

impl RulesState {
    pub fn load(maps: &BpfMaps) -> Result<Vec<PolicyRule>> {
        maps.list_all_metadata()
            .context("Failed to load rules from BPF metadata map")
    }

    pub fn add_rule(maps: &BpfMaps, rule: &PolicyRule) -> Result<()> {
        let parsed_rule = rule.to_rule().context("Failed to convert policy rule")?;

        let action = match parsed_rule.action {
            crate::models::rule::Action::Allow => 1,
            crate::models::rule::Action::Drop => 0,
        };

        maps.update_rule(&parsed_rule, action)
            .context("Failed to update firewall rule")?;

        maps.add_rule_metadata(
            &rule.name,
            &parsed_rule,
            action,
            rule.description.as_deref(),
        )
        .context("Failed to add rule metadata")?;

        Ok(())
    }

    pub fn get_rule(maps: &BpfMaps, name: &str) -> Result<Option<PolicyRule>> {
        maps.get_rule_metadata(name)
            .context("Failed to get rule metadata from BPF map")
    }

    pub fn delete_rule(maps: &BpfMaps, name: &str) -> Result<Option<PolicyRule>> {
        let policy_rule = maps
            .get_rule_metadata(name)
            .context("Failed to get rule metadata")?;

        if let Some(policy_rule) = policy_rule {
            let rule = policy_rule
                .to_rule()
                .context("Failed to convert policy rule for deletion")?;

            maps.remove_rule(&rule)
                .context("Failed to remove firewall rule")?;

            maps.delete_rule_metadata(name)
                .context("Failed to remove rule metadata")?;

            Ok(Some(policy_rule))
        } else {
            Ok(None)
        }
    }

    pub fn list_rules(maps: &BpfMaps) -> Result<Vec<PolicyRule>> {
        Self::load(maps)
    }
}

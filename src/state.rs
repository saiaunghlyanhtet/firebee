use crate::bpf_user::maps::BpfMaps;
use crate::policy::PolicyRule;
use anyhow::{Context, Result};

/// RulesState now operates directly on BPF maps instead of files
/// This provides a single source of truth and ensures consistency
pub struct RulesState;

impl RulesState {
    /// Load all rules from BPF metadata map
    pub fn load(maps: &BpfMaps) -> Result<Vec<PolicyRule>> {
        maps.list_all_metadata()
            .context("Failed to load rules from BPF metadata map")
    }

    /// Add a rule to both BPF maps (rules + metadata)
    pub fn add_rule(maps: &BpfMaps, rule: &PolicyRule) -> Result<()> {
        let parsed_rule = rule.to_rule().context("Failed to convert policy rule")?;

        let action = match parsed_rule.action {
            crate::models::rule::Action::Allow => 1,
            crate::models::rule::Action::Drop => 0,
        };

        // Update the firewall rule
        maps.update_rule(&parsed_rule, action)
            .context("Failed to update firewall rule")?;

        // Update the metadata
        maps.add_rule_metadata(
            &rule.name,
            &parsed_rule,
            action,
            rule.description.as_deref(),
        )
        .context("Failed to add rule metadata")?;

        Ok(())
    }

    /// Get a specific rule by name from BPF metadata map
    pub fn get_rule(maps: &BpfMaps, name: &str) -> Result<Option<PolicyRule>> {
        maps.get_rule_metadata(name)
            .context("Failed to get rule metadata from BPF map")
    }

    /// Delete a rule from both BPF maps
    pub fn delete_rule(maps: &BpfMaps, name: &str) -> Result<Option<PolicyRule>> {
        // First get the metadata to find the rule details
        let policy_rule = maps
            .get_rule_metadata(name)
            .context("Failed to get rule metadata")?;

        if let Some(policy_rule) = policy_rule {
            let rule = policy_rule
                .to_rule()
                .context("Failed to convert policy rule for deletion")?;

            // Delete from firewall rules map
            maps.remove_rule(&rule)
                .context("Failed to remove firewall rule")?;

            // Delete from metadata map
            maps.delete_rule_metadata(name)
                .context("Failed to remove rule metadata")?;

            Ok(Some(policy_rule))
        } else {
            Ok(None)
        }
    }

    /// List all rules from BPF metadata map
    pub fn list_rules(maps: &BpfMaps) -> Result<Vec<PolicyRule>> {
        Self::load(maps)
    }
}

use crate::bpf_user::maps::BpfMaps;
use crate::dns::cache::DnsCache;
use crate::dns::parser::{parse_dns_response, DnsIp};
use crate::models::rule::{Action, Direction, Protocol};
use crate::policy::PolicyRule;
use crate::state::RulesState;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct FqdnRule {
    pub domain: String,
    pub action: Action,
    pub protocol: Protocol,
    pub direction: Direction,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
}

impl FqdnRule {
    /// Build from a PolicyRule that has a domain set.
    pub fn from_policy_rule(pr: &PolicyRule) -> Option<Self> {
        let domain = pr.domain.as_ref()?.to_lowercase();
        let parsed = pr.to_rule().ok()?;
        Some(FqdnRule {
            domain,
            action: parsed.action,
            protocol: parsed.protocol,
            direction: parsed.direction,
            src_port: parsed.src_port,
            dst_port: parsed.dst_port,
        })
    }

    /// Generate a unique BPF rule name for an IP resolved from this FQDN rule.
    fn bpf_rule_name(&self, ip: &IpAddr) -> String {
        format!("fqdn:{}:{}", self.domain, ip)
    }

    /// Create a PolicyRule representation for adding to BPF maps.
    fn to_policy_rule_for_ip(&self, ip: IpAddr) -> PolicyRule {
        let action = match self.action {
            Action::Allow => "allow",
            Action::Drop => "drop",
        };
        let protocol = match self.protocol {
            Protocol::TCP => "tcp",
            Protocol::UDP => "udp",
            Protocol::ICMP => "icmp",
            Protocol::Any => "any",
        };
        let direction = match self.direction {
            Direction::Ingress => "ingress",
            Direction::Egress => "egress",
            Direction::Both => "both",
        };
        PolicyRule {
            name: self.bpf_rule_name(&ip),
            ip: format!("{}/32", ip),
            action: action.to_string(),
            description: Some(format!("FQDN: {}", self.domain)),
            protocol: protocol.to_string(),
            src_port: self.src_port,
            dst_port: self.dst_port,
            direction: direction.to_string(),
            domain: None, // concrete rule, not FQDN
        }
    }

    /// Check whether a DNS response domain matches this FQDN rule.
    /// Supports exact match and wildcard prefix (e.g., "*.example.com").
    pub fn matches_domain(&self, queried: &str) -> bool {
        let pattern = &self.domain;
        let queried = queried.to_lowercase();

        if let Some(suffix) = pattern.strip_prefix("*.") {
            queried == suffix || queried.ends_with(&format!(".{}", suffix))
        } else {
            queried == *pattern
        }
    }
}

/// State shared between the DNS monitor thread and the main application.
pub struct DnsMonitorState {
    pub fqdn_rules: Vec<FqdnRule>,
    pub cache: DnsCache,
    /// Track which BPF rule names we've installed for FQDN rules,
    /// so we can clean them up on TTL expiry.
    pub installed_rules: HashMap<String, IpAddr>,
}

impl DnsMonitorState {
    pub fn new(fqdn_rules: Vec<FqdnRule>) -> Self {
        Self {
            fqdn_rules,
            cache: DnsCache::new(Duration::from_secs(30)),
            installed_rules: HashMap::new(),
        }
    }
}

/// Process a raw DNS event from the BPF ring buffer.
/// Parses the DNS response, checks against FQDN rules, and updates BPF maps.
pub fn handle_dns_event(data: &[u8], state: &Arc<Mutex<DnsMonitorState>>, maps: &BpfMaps) {
    if data.len() < 8 {
        return;
    }

    let dns_len = u16::from_ne_bytes([data[4], data[5]]) as usize;
    let dns_data = &data[8..];

    if dns_len == 0 || dns_len > dns_data.len() {
        return;
    }

    let dns_payload = &dns_data[..dns_len];
    let response = match parse_dns_response(dns_payload) {
        Some(r) => r,
        None => return,
    };

    let mut state = match state.lock() {
        Ok(s) => s,
        Err(_) => return,
    };

    let matching_rules: Vec<FqdnRule> = state
        .fqdn_rules
        .iter()
        .filter(|r| r.matches_domain(&response.query_name))
        .cloned()
        .collect();

    if matching_rules.is_empty() {
        return;
    }

    println!(
        "[dns] Response for '{}': {} answer(s), matches {} FQDN rule(s)",
        response.query_name,
        response.answers.len(),
        matching_rules.len()
    );

    for answer in &response.answers {
        let ip: IpAddr = match &answer.ip {
            DnsIp::V4(v4) => IpAddr::V4(*v4),
            DnsIp::V6(v6) => IpAddr::V6(*v6),
        };

        let ttl = Duration::from_secs(answer.ttl as u64);
        let is_new = state.cache.insert(&response.query_name, ip, ttl);

        if !is_new {
            continue;
        }

        for fqdn_rule in &matching_rules {
            let policy_rule = fqdn_rule.to_policy_rule_for_ip(ip);
            let rule_name = fqdn_rule.bpf_rule_name(&ip);

            match RulesState::add_rule(maps, &policy_rule) {
                Ok(()) => {
                    println!(
                        "[dns] ✓ Installed FQDN rule '{}' -> {} (TTL {}s)",
                        rule_name, ip, answer.ttl
                    );
                    state.installed_rules.insert(rule_name, ip);
                }
                Err(e) => {
                    eprintln!("[dns] ✗ Failed to install FQDN rule '{}': {}", rule_name, e);
                }
            }
        }
    }
}

/// Sweep expired DNS cache entries and remove their BPF rules.
pub fn sweep_expired_rules(state: &Arc<Mutex<DnsMonitorState>>, maps: &BpfMaps) {
    let mut state = match state.lock() {
        Ok(s) => s,
        Err(_) => return,
    };

    let expired = state.cache.sweep_expired();

    for (domain, ip) in &expired {
        let matching_rules: Vec<FqdnRule> = state
            .fqdn_rules
            .iter()
            .filter(|r| r.matches_domain(domain))
            .cloned()
            .collect();

        for fqdn_rule in &matching_rules {
            let rule_name = fqdn_rule.bpf_rule_name(ip);

            if state.installed_rules.remove(&rule_name).is_some() {
                match RulesState::delete_rule(maps, &rule_name) {
                    Ok(Some(_)) => {
                        println!("[dns] Removed expired FQDN rule '{}' ({})", rule_name, ip);
                    }
                    Ok(None) => {
                        log::warn!("FQDN rule '{}' was already gone from BPF maps", rule_name);
                    }
                    Err(e) => {
                        eprintln!(
                            "[dns] Failed to remove expired FQDN rule '{}': {}",
                            rule_name, e
                        );
                    }
                }
            }
        }
    }
}

pub fn extract_fqdn_rules(rules: &[PolicyRule]) -> Vec<FqdnRule> {
    rules
        .iter()
        .filter(|r| r.is_fqdn_rule())
        .filter_map(FqdnRule::from_policy_rule)
        .collect()
}

/// Pre-resolve FQDN rules via system DNS and install BPF rules immediately.
/// This ensures blocking works even if the process exits before any DNS traffic
/// is observed by the BPF ring buffer monitor.
pub fn pre_resolve_fqdn_rules(fqdn_rules: &[FqdnRule], maps: &BpfMaps) {
    use std::net::ToSocketAddrs;

    for fqdn_rule in fqdn_rules {
        // Strip wildcard prefix for resolution — resolve the base domain
        let lookup_domain = fqdn_rule
            .domain
            .strip_prefix("*.")
            .unwrap_or(&fqdn_rule.domain);

        // Use system resolver (respects /etc/resolv.conf)
        let addrs = match (lookup_domain, 0u16).to_socket_addrs() {
            Ok(addrs) => addrs,
            Err(e) => {
                eprintln!("[dns] Pre-resolve failed for '{}': {}", lookup_domain, e);
                continue;
            }
        };

        let mut count = 0;
        for addr in addrs {
            let ip = addr.ip();
            let policy_rule = fqdn_rule.to_policy_rule_for_ip(ip);
            let rule_name = fqdn_rule.bpf_rule_name(&ip);

            match RulesState::add_rule(maps, &policy_rule) {
                Ok(()) => {
                    println!(
                        "[dns] ✓ Pre-resolved '{}' -> {} ({})",
                        lookup_domain, ip, rule_name
                    );
                    count += 1;
                }
                Err(e) => {
                    eprintln!(
                        "[dns] ✗ Failed to install pre-resolved rule '{}': {}",
                        rule_name, e
                    );
                }
            }
        }

        if count == 0 {
            eprintln!("[dns] No addresses resolved for '{}'", lookup_domain);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matches_exact_domain() {
        let rule = FqdnRule {
            domain: "example.com".to_string(),
            action: Action::Drop,
            protocol: Protocol::Any,
            direction: Direction::Both,
            src_port: None,
            dst_port: None,
        };

        assert!(rule.matches_domain("example.com"));
        assert!(rule.matches_domain("Example.COM"));
        assert!(!rule.matches_domain("sub.example.com"));
        assert!(!rule.matches_domain("notexample.com"));
    }

    #[test]
    fn test_matches_wildcard_domain() {
        let rule = FqdnRule {
            domain: "*.example.com".to_string(),
            action: Action::Drop,
            protocol: Protocol::Any,
            direction: Direction::Both,
            src_port: None,
            dst_port: None,
        };

        assert!(rule.matches_domain("sub.example.com"));
        assert!(rule.matches_domain("deep.sub.example.com"));
        assert!(rule.matches_domain("example.com")); // wildcard also matches bare domain
        assert!(!rule.matches_domain("notexample.com"));
    }

    #[test]
    fn test_extract_fqdn_rules() {
        let rules = vec![
            PolicyRule {
                name: "block-ads".to_string(),
                ip: String::new(),
                action: "drop".to_string(),
                description: None,
                protocol: "any".to_string(),
                src_port: None,
                dst_port: None,
                direction: "both".to_string(),
                domain: Some("ads.example.com".to_string()),
            },
            PolicyRule {
                name: "allow-local".to_string(),
                ip: "192.168.1.0/24".to_string(),
                action: "allow".to_string(),
                description: None,
                protocol: "any".to_string(),
                src_port: None,
                dst_port: None,
                direction: "ingress".to_string(),
                domain: None,
            },
        ];

        let fqdn_rules = extract_fqdn_rules(&rules);
        assert_eq!(fqdn_rules.len(), 1);
        assert_eq!(fqdn_rules[0].domain, "ads.example.com");
    }

    #[test]
    fn test_bpf_rule_name() {
        let rule = FqdnRule {
            domain: "example.com".to_string(),
            action: Action::Drop,
            protocol: Protocol::Any,
            direction: Direction::Both,
            src_port: None,
            dst_port: None,
        };
        let ip = IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(rule.bpf_rule_name(&ip), "fqdn:example.com:1.2.3.4");
    }
}

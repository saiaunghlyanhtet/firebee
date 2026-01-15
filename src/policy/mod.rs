mod parser;
mod validator;

pub use parser::{parse_policy_file, PolicyFile, PolicyRule};
pub use validator::validate_policy;

#[cfg(test)]
mod integration_tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_parse_valid_json_policy() {
        let temp_dir = TempDir::new().unwrap();
        let policy_path = temp_dir.path().join("policy.json");

        let json_content = r#"{
            "rules": [
                {
                    "name": "block_malicious",
                    "ip": "192.168.1.100",
                    "action": "drop",
                    "protocol": "tcp",
                    "direction": "ingress",
                    "description": "Block known malicious IP"
                },
                {
                    "name": "allow_dns",
                    "ip": "8.8.8.8",
                    "action": "allow",
                    "protocol": "udp",
                    "dst_port": 53,
                    "direction": "egress"
                }
            ]
        }"#;

        fs::write(&policy_path, json_content).unwrap();
        let policy = parse_policy_file(&policy_path).unwrap();

        assert_eq!(policy.rules.len(), 2);
        assert_eq!(policy.rules[0].name, "block_malicious");
        assert_eq!(policy.rules[1].dst_port, Some(53));
    }

    #[test]
    fn test_parse_valid_yaml_policy() {
        let temp_dir = TempDir::new().unwrap();
        let policy_path = temp_dir.path().join("policy.yaml");

        let yaml_content = r#"
rules:
  - name: block_scanner
    ip: 10.0.0.50
    action: drop
    protocol: any
    direction: ingress
    description: Block port scanner
  - name: allow_web
    ip: 192.168.1.0/24
    action: allow
    protocol: tcp
    dst_port: 80
    direction: both
"#;

        fs::write(&policy_path, yaml_content).unwrap();
        let policy = parse_policy_file(&policy_path).unwrap();

        assert_eq!(policy.rules.len(), 2);
        assert_eq!(policy.rules[0].name, "block_scanner");
        assert_eq!(policy.rules[1].ip, "192.168.1.0/24");
    }

    #[test]
    fn test_parse_and_validate_complete_workflow() {
        let temp_dir = TempDir::new().unwrap();
        let policy_path = temp_dir.path().join("complete.json");

        let json_content = r#"{
            "rules": [
                {
                    "name": "rule1",
                    "ip": "192.168.1.1",
                    "action": "allow",
                    "protocol": "tcp",
                    "src_port": 8080,
                    "dst_port": 443,
                    "direction": "ingress"
                },
                {
                    "name": "rule2",
                    "ip": "10.0.0.0/8",
                    "action": "drop",
                    "protocol": "any",
                    "direction": "both",
                    "description": "Block private network"
                }
            ]
        }"#;

        fs::write(&policy_path, json_content).unwrap();

        // Parse the policy
        let policy = parse_policy_file(&policy_path).unwrap();

        // Validate it
        assert!(validate_policy(&policy).is_ok());

        // Convert rules
        for rule in &policy.rules {
            assert!(rule.to_rule().is_ok());
        }
    }

    #[test]
    fn test_parse_invalid_json() {
        let temp_dir = TempDir::new().unwrap();
        let policy_path = temp_dir.path().join("invalid.json");

        let invalid_json = r#"{ "rules": [ { invalid json } ] }"#;

        fs::write(&policy_path, invalid_json).unwrap();
        let result = parse_policy_file(&policy_path);

        assert!(result.is_err());
    }

    #[test]
    fn test_parse_nonexistent_file() {
        let result = parse_policy_file("/nonexistent/path/policy.json");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_policy_with_duplicate_names() {
        let temp_dir = TempDir::new().unwrap();
        let policy_path = temp_dir.path().join("duplicate.yaml");

        let yaml_content = r#"
rules:
  - name: same_name
    ip: 192.168.1.1
    action: allow
  - name: same_name
    ip: 192.168.1.2
    action: drop
"#;

        fs::write(&policy_path, yaml_content).unwrap();
        let policy = parse_policy_file(&policy_path).unwrap();
        let result = validate_policy(&policy);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("duplicate"));
    }

    #[test]
    fn test_validate_empty_policy() {
        let temp_dir = TempDir::new().unwrap();
        let policy_path = temp_dir.path().join("empty.json");

        let json_content = r#"{ "rules": [] }"#;

        fs::write(&policy_path, json_content).unwrap();
        let policy = parse_policy_file(&policy_path).unwrap();
        let result = validate_policy(&policy);

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("at least one rule"));
    }

    #[test]
    fn test_yaml_with_yml_extension() {
        let temp_dir = TempDir::new().unwrap();
        let policy_path = temp_dir.path().join("policy.yml");

        let yaml_content = r#"
rules:
  - name: test_rule
    ip: 192.168.1.1
    action: allow
    protocol: tcp
    direction: ingress
"#;

        fs::write(&policy_path, yaml_content).unwrap();
        let policy = parse_policy_file(&policy_path).unwrap();

        assert_eq!(policy.rules.len(), 1);
        assert_eq!(policy.rules[0].name, "test_rule");
    }

    #[test]
    fn test_policy_with_defaults() {
        let temp_dir = TempDir::new().unwrap();
        let policy_path = temp_dir.path().join("defaults.json");

        // Minimal rule relying on defaults
        let json_content = r#"{
            "rules": [
                {
                    "name": "minimal_rule",
                    "ip": "192.168.1.1",
                    "action": "allow"
                }
            ]
        }"#;

        fs::write(&policy_path, json_content).unwrap();
        let policy = parse_policy_file(&policy_path).unwrap();

        assert_eq!(policy.rules[0].protocol, "any");
        assert_eq!(policy.rules[0].direction, "ingress");
        assert!(policy.rules[0].description.is_none());
        assert!(policy.rules[0].src_port.is_none());
        assert!(policy.rules[0].dst_port.is_none());
    }

    #[test]
    fn test_large_policy_file() {
        let temp_dir = TempDir::new().unwrap();
        let policy_path = temp_dir.path().join("large.json");

        let mut rules = Vec::new();
        for i in 0..100 {
            rules.push(format!(
                r#"{{
                    "name": "rule_{}",
                    "ip": "192.168.{}.{}",
                    "action": "{}",
                    "protocol": "{}",
                    "direction": "{}"
                }}"#,
                i,
                i / 256,
                i % 256,
                if i % 2 == 0 { "allow" } else { "drop" },
                match i % 4 {
                    0 => "tcp",
                    1 => "udp",
                    2 => "icmp",
                    _ => "any",
                },
                match i % 3 {
                    0 => "ingress",
                    1 => "egress",
                    _ => "both",
                }
            ));
        }

        let json_content = format!(r#"{{ "rules": [{}] }}"#, rules.join(","));
        fs::write(&policy_path, json_content).unwrap();

        let policy = parse_policy_file(&policy_path).unwrap();
        assert_eq!(policy.rules.len(), 100);

        // Validate the entire policy
        assert!(validate_policy(&policy).is_ok());
    }

    #[test]
    fn test_policy_with_cidr_ranges() {
        let temp_dir = TempDir::new().unwrap();
        let policy_path = temp_dir.path().join("cidr.yaml");

        let yaml_content = r#"
rules:
  - name: block_class_a
    ip: 10.0.0.0/8
    action: drop
  - name: block_class_b
    ip: 172.16.0.0/12
    action: drop
  - name: block_class_c
    ip: 192.168.0.0/16
    action: drop
  - name: allow_specific
    ip: 192.168.1.100/32
    action: allow
"#;

        fs::write(&policy_path, yaml_content).unwrap();
        let policy = parse_policy_file(&policy_path).unwrap();

        assert_eq!(policy.rules.len(), 4);
        assert!(validate_policy(&policy).is_ok());

        // Verify all rules can be converted
        for rule in &policy.rules {
            let parsed = rule.to_rule().unwrap();
            assert!(parsed.subnet_mask.is_some());
        }
    }

    #[test]
    fn test_policy_with_all_protocols() {
        let temp_dir = TempDir::new().unwrap();
        let policy_path = temp_dir.path().join("protocols.json");

        let json_content = r#"{
            "rules": [
                {
                    "name": "tcp_rule",
                    "ip": "192.168.1.1",
                    "action": "allow",
                    "protocol": "tcp"
                },
                {
                    "name": "udp_rule",
                    "ip": "192.168.1.2",
                    "action": "allow",
                    "protocol": "udp"
                },
                {
                    "name": "icmp_rule",
                    "ip": "192.168.1.3",
                    "action": "allow",
                    "protocol": "icmp"
                },
                {
                    "name": "any_rule",
                    "ip": "192.168.1.4",
                    "action": "allow",
                    "protocol": "any"
                }
            ]
        }"#;

        fs::write(&policy_path, json_content).unwrap();
        let policy = parse_policy_file(&policy_path).unwrap();

        assert_eq!(policy.rules.len(), 4);
        assert!(validate_policy(&policy).is_ok());
    }
}

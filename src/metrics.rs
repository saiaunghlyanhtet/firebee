use crate::bpf_user::maps::BpfMaps;
use crate::policy::PolicyRule;
use std::collections::HashMap;

pub fn format_prometheus(maps: &BpfMaps) -> String {
    let metadata_list = maps.list_all_metadata().unwrap_or_default();
    let stats = maps.get_stats_by_name().unwrap_or_default();

    let meta_by_name: HashMap<&str, &PolicyRule> =
        metadata_list.iter().map(|r| (r.name.as_str(), r)).collect();

    let mut out = String::new();

    write_header(
        &mut out,
        "gauge",
        "firebee_up",
        "1 if BPF maps are reachable, 0 otherwise",
    );
    out.push_str("firebee_up 1\n\n");

    write_header(
        &mut out,
        "gauge",
        "firebee_active_rules",
        "Number of active firewall rules",
    );
    out.push_str(&format!("firebee_active_rules {}\n\n", metadata_list.len()));

    // Sort for deterministic output
    let mut sorted: Vec<_> = stats.iter().collect();
    sorted.sort_by_key(|(name, _)| name.as_str());

    write_header(
        &mut out,
        "counter",
        "firebee_rule_packets_total",
        "Total packets matched by this firewall rule",
    );
    for (name, (packets, _)) in &sorted {
        let labels = rule_labels(name, meta_by_name.get(name.as_str()));
        out.push_str(&format!(
            "firebee_rule_packets_total{{{labels}}} {packets}\n"
        ));
    }

    out.push('\n');
    write_header(
        &mut out,
        "counter",
        "firebee_rule_bytes_total",
        "Total bytes matched by this firewall rule",
    );
    for (name, (_, bytes)) in &sorted {
        let labels = rule_labels(name, meta_by_name.get(name.as_str()));
        out.push_str(&format!("firebee_rule_bytes_total{{{labels}}} {bytes}\n"));
    }

    out
}

fn write_header(out: &mut String, typ: &str, name: &str, help: &str) {
    out.push_str(&format!("# HELP {name} {help}\n"));
    out.push_str(&format!("# TYPE {name} {typ}\n"));
}

fn rule_labels(name: &str, meta: Option<&&PolicyRule>) -> String {
    let n = escape_label_value(name);
    match meta {
        Some(r) => format!(
            "rule=\"{n}\",action=\"{}\",direction=\"{}\",protocol=\"{}\"",
            r.action, r.direction, r.protocol
        ),
        None => format!("rule=\"{n}\""),
    }
}

fn escape_label_value(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace(['*', ':'], "_")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_label_value_clean() {
        assert_eq!(escape_label_value("my-rule"), "my-rule");
    }

    #[test]
    fn test_escape_label_value_quotes() {
        assert_eq!(escape_label_value("say \"hi\""), "say \\\"hi\\\"");
    }

    #[test]
    fn test_escape_label_value_backslash() {
        assert_eq!(escape_label_value("a\\b"), "a\\\\b");
    }

    #[test]
    fn test_escape_label_value_fqdn() {
        assert_eq!(
            escape_label_value("fqdn:*.pornhub.com:66.254.114.41"),
            "fqdn__.pornhub.com_66.254.114.41"
        );
    }

    #[test]
    fn test_rule_labels_without_meta() {
        let labels = rule_labels("block-ads", None);
        assert_eq!(labels, "rule=\"block-ads\"");
    }

    #[test]
    fn test_rule_labels_with_meta() {
        let rule = PolicyRule {
            name: "block-ads".into(),
            ip: "1.2.3.4".into(),
            action: "drop".into(),
            protocol: "tcp".into(),
            direction: "ingress".into(),
            src_port: None,
            dst_port: None,
            description: None,
            domain: None,
        };
        let labels = rule_labels("block-ads", Some(&&rule));
        assert_eq!(
            labels,
            "rule=\"block-ads\",action=\"drop\",direction=\"ingress\",protocol=\"tcp\""
        );
    }
}

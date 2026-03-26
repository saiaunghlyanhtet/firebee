# Firebee Policy File Format

Policy files define firewall rules in YAML or JSON format. YAML is the default and recommended format.

## Structure

### YAML Format (Recommended)

```yaml
rules:
  - name: rule_name
    ip: IP_ADDRESS
    action: allow|drop
    protocol: tcp|udp|icmp|any
    direction: ingress|egress|both
    description: Optional description

  # FQDN rule (domain instead of ip)
  - name: block_ads
    domain: "*.ads.example.com"
    action: drop
    direction: both
```

### JSON Format

```json
{
  "rules": [
    {
      "name": "rule_name",
      "ip": "IP_ADDRESS",
      "action": "allow|drop",
      "protocol": "tcp|udp|icmp|any",
      "direction": "ingress|egress|both",
      "description": "Optional description"
    }
  ]
}
```

## Fields

- **rules** (required): Array of rule objects

### Rule Object

- **name** (required): Unique identifier for the rule
- **ip** (required unless `domain` is set): IPv4 address to match (e.g., "192.168.1.1" or "192.168.0.0/24")
- **domain** (optional): Domain name for FQDN-based rules (e.g., "ads.example.com" or "*.tracking.com"). When set, `ip` should be omitted — IPs are resolved dynamically from DNS responses.
- **action** (required): Action to take. Valid values:
  - Allow: `allow`, `pass`, `accept`
  - Drop: `drop`, `deny`, `block`
- **protocol** (optional, default: `any`): Network protocol to match:
  - `tcp` - TCP protocol
  - `udp` - UDP protocol
  - `icmp` - ICMP protocol
  - `any` - All protocols
- **direction** (optional, default: `ingress`): Traffic direction:
  - `ingress`, `in`, `input` - Incoming traffic (default for XDP)
  - `egress`, `out`, `output` - Outgoing traffic (requires future TC-BPF support)
  - `both`, `any` - Both directions
- **src_port** (optional): Source port to match (0 or omit for any)
- **dst_port** (optional): Destination port to match (0 or omit for any)
- **description** (optional): Human-readable description of the rule

> **Note:** Each rule must specify either `ip` or `domain`, but not both.

## Validation Rules

1. Each rule must have a unique name
2. Each rule must specify either `ip` or `domain`, but not both
3. IP addresses must be valid IPv4 format or CIDR notation
4. Domain names must be non-empty; wildcards use `*.` prefix (e.g., `*.example.com`)
5. Actions must be one of the allowed values
6. Protocols must be tcp, udp, icmp, or any
7. Directions must be ingress, egress, or both
8. Policy file must contain at least one rule

## Important Notes

### FQDN (Domain-Based) Rules
- FQDN rules use passive DNS sniffing to resolve domain names to IP addresses
- When a DNS response is seen for a matching domain, firebee automatically installs BPF rules for the resolved IPs
- Resolved IP rules are named `fqdn:<domain>:<ip>` and are automatically removed when the DNS TTL expires
- Wildcard domains are supported: `*.example.com` matches `sub.example.com`, `deep.sub.example.com`, and `example.com` itself
- FQDN rules require the XDP/TC programs to be loaded (via `firebee run` or `firebee add --attach`)
- A minimum TTL floor of 30 seconds is applied to prevent excessive rule churn

### Direction Field
- **XDP Limitation**: The current XDP implementation only processes ingress (incoming) traffic
- Rules with `direction: egress` will be stored but won't match traffic until TC-BPF egress support is added
- Use `direction: both` for rules that should apply to both directions (currently only ingress)
- Default direction is `ingress` if not specified

## Example

See `example-policy.yaml` for a complete YAML example.

## Format Detection

The file format is automatically detected based on the file extension:
- `.yaml` or `.yml` - parsed as YAML
- `.json` - parsed as JSON
- No extension or other - defaults to YAML

## Usage

### Add rules from a policy file (with existing firebee instance):
```bash
sudo firebee add --policy policy.yaml
```

### Add rules from JSON file:
```bash
sudo firebee add --policy policy.json
```

### Add rules and attach to interface:
```bash
sudo firebee add --policy policy.yaml --interface wlp4s0 --attach
```

### Run TUI mode:
```bash
sudo firebee run wlp4s0
```

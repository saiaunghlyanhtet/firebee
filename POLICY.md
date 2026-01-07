# Firebee Policy File Format

Policy files define firewall rules in YAML or JSON format. YAML is the default and recommended format.

## Structure

### YAML Format (Recommended)

```yaml
rules:
  - name: rule_name
    ip: IP_ADDRESS
    action: allow|drop
    description: Optional description
```

### JSON Format

```json
{
  "rules": [
    {
      "name": "rule_name",
      "ip": "IP_ADDRESS",
      "action": "allow|drop",
      "description": "Optional description"
    }
  ]
}
```

## Fields

- **rules** (required): Array of rule objects

### Rule Object

- **name** (required): Unique identifier for the rule
- **ip** (required): IPv4 address to match (e.g., "192.168.1.1")
- **action** (required): Action to take. Valid values:
  - Allow: `allow`, `pass`, `accept`
  - Drop: `drop`, `deny`, `block`
- **description** (optional): Human-readable description of the rule

## Validation Rules

1. Each rule must have a unique name
2. IP addresses must be valid IPv4 format
3. Actions must be one of the allowed values
4. Policy file must contain at least one rule

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

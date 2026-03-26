# Firebee

An eBPF-based network firewall for Linux that uses XDP (eXpress Data Path) for high-performance ingress packet filtering and TC-BPF (Traffic Control) for egress filtering. Firebee provides a declarative policy file format, a CLI for rule management, and a real-time terminal UI (TUI) for monitoring traffic.

## Features

- **XDP ingress filtering** — Drops or allows packets at the earliest point in the network stack, before the kernel allocates an `sk_buff`, for near line-rate performance.
- **TC-BPF egress filtering** — Filters outgoing traffic using the Linux Traffic Control subsystem.
- **IPv4 and IPv6 support** — Rules can target individual IPs or CIDR ranges for both address families.
- **Protocol and port matching** — Filter by TCP, UDP, ICMP, or any protocol, with optional source/destination port constraints.
- **Declarative policy files** — Define rules in YAML or JSON; firebee validates and loads them.
- **Per-rule statistics** — Track packet and byte counts per rule in real time.
- **Terminal UI** — A ratatui-based TUI shows active rules, live packet logs from a BPF ring buffer, and per-rule stats.
- **Pinned BPF maps** — Maps are pinned to `/sys/fs/bpf/firebee/` so rules persist across CLI invocations and multiple tools can interact with the running firewall.

## Prerequisites

- Linux kernel ≥ 5.15 (with BPF and XDP support)
- `clang` and `llvm` (for compiling BPF C programs)
- `libelf-dev`, `libbpf-dev`, `pkg-config`
- Linux headers for your kernel (`linux-headers-$(uname -r)`)
- Rust toolchain (stable)
- Root privileges (or `CAP_BPF` + `CAP_NET_ADMIN`) to load BPF programs

### Install dependencies (Debian/Ubuntu)

```bash
sudo apt-get install -y \
  llvm clang libelf-dev libbpf-dev linux-headers-$(uname -r) \
  linux-libc-dev build-essential pkg-config
```

## Building

```bash
make build
```

This runs `cargo build --release` (compiles the Rust userspace binary) and `cargo libbpf build` (compiles the BPF C programs into `.bpf.o` object files under `target/bpf/`).

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    Userspace (Rust)                       │
│                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────┐  │
│  │   CLI    │  │  Policy  │  │  State   │  │   TUI   │  │
│  │ (clap)   │  │ Parser & │  │ Manager  │  │(ratatui)│  │
│  │          │  │Validator │  │          │  │         │  │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬────┘  │
│       │              │             │              │       │
│       └──────────────┴─────┬───────┴──────────────┘       │
│                            │                              │
│                    ┌───────▼────────┐                     │
│                    │   BPF Loader   │                     │
│                    │   & Maps API   │                     │
│                    └───────┬────────┘                     │
└────────────────────────────┼─────────────────────────────┘
                             │  libbpf-rs
                   ┌─────────▼──────────┐
                   │   Pinned BPF Maps  │
                   │ /sys/fs/bpf/firebee│
                   └─────────┬──────────┘
                             │
            ┌────────────────┼────────────────┐
            │                │                │
   ┌────────▼──────┐  ┌─────▼──────┐  ┌──────▼───────┐
   │  XDP Program  │  │ TC Egress  │  │  Ring Buffer │
   │  (ingress)    │  │  Program   │  │  (log_events)│
   │  firebee.bpf.c│  │firebee_    │  │              │
   │               │  │egress.bpf.c│  │              │
   └───────────────┘  └────────────┘  └──────────────┘
          Kernel space (eBPF)
```

### Major Components

#### 1. CLI (`src/main.rs`)

The entry point. Uses [clap](https://docs.rs/clap) to expose these subcommands:

| Command | Description |
|---------|------------|
| `run <interface>` | Attach the XDP/TC programs to a network interface and optionally load a policy file. |
| `ui` | Launch the terminal UI to monitor an already-running firewall. |
| `add --policy <file>` | Parse and load rules from a YAML/JSON policy file into the running firewall. |
| `get rule [name]` | Print one or all active rules (YAML or JSON output). |
| `delete rule <name>` | Remove a rule by name. |
| `stats show` | Display per-rule packet/byte statistics. |
| `stats reset` | Reset all counters to zero. |

#### 2. BPF Programs (`src/bpf/`)

- **`firebee.bpf.c`** — The XDP program (`xdp_firewall`). Attached to a network interface, it inspects every incoming packet: parses Ethernet/IP/IPv6 headers, extracts protocol and ports, iterates through the rules array map to find a match (with CIDR, protocol, port, and direction checks), logs the decision to a ring buffer, and returns `XDP_DROP` or `XDP_PASS`.
- **`firebee_egress.bpf.c`** — The TC-BPF program (`tc_egress_firewall`). Attached via the Traffic Control egress hook, it performs the same matching logic on outgoing packets, returning `TC_ACT_SHOT` (drop) or `TC_ACT_OK` (pass).
- **`firebee_common.h`** — Shared struct definitions (`rule_entry`, `rule_entry_v6`, `rule_metadata`, `log_event`, `rule_stats`) used by both kernel and userspace.
- **`firebee_helpers.h`** — BPF helper functions for port extraction, rule matching, and IPv6 prefix comparison.
- **`firebee_test.bpf.c`** — Kernel-side BPF unit tests using Cilium-style `CHECK`/`TEST` macros.

BPF maps used:

| Map | Type | Purpose |
|-----|------|---------|
| `rules_map` | Array | IPv4 rule entries for fast iteration |
| `rules_map_v6` | Array | IPv6 rule entries |
| `rule_metadata_map` | Hash | Human-readable metadata (name, description) keyed by index |
| `rule_stats_map` | Array | Per-rule packet/byte counters |
| `log_events` | Ring Buffer | Real-time packet log events sent to userspace |

#### 3. BPF Userspace Layer (`src/bpf_user/`)

- **`loader.rs`** — `BpfLoader` opens the compiled `.bpf.o` files, pins all maps to `/sys/fs/bpf/firebee/`, attaches the XDP program to the given interface, and optionally loads the TC egress program.
- **`maps.rs`** — `BpfMaps` provides a safe Rust API over the pinned BPF maps: add/remove/list rules, read/write metadata, get/reset statistics, and interact with both IPv4 and IPv6 rule maps.
- **`handler.rs`** — `BpfHandler` runs the event loop: listens for commands (add rule, remove rule, unload) and polls the ring buffer for log events.

#### 4. Policy Engine (`src/policy/`)

- **`parser.rs`** — Reads a `.yaml`/`.yml` or `.json` file, deserialises it into a `PolicyFile` containing a list of `PolicyRule` structs. Supports IPv4, IPv6, CIDR notation, protocol, direction, and port fields.
- **`validator.rs`** — Validates the parsed policy: checks for non-empty rules, unique names, valid IP addresses, valid actions (`allow`/`pass`/`accept`/`drop`/`deny`/`block`), and valid protocols/directions.

#### 5. State Manager (`src/state.rs`)

`RulesState` bridges the policy layer and the BPF maps. It converts `PolicyRule` objects into kernel-level `Rule` structs and calls the maps API to add, get, delete, or list rules.

#### 6. Terminal UI (`src/ui/`)

Built with [ratatui](https://docs.rs/ratatui) and [crossterm](https://docs.rs/crossterm):

- **`app.rs`** — Application state: active rules, log buffer, per-rule stats, input mode.
- **`widgets.rs`** — Renders a rules table (name, IP, protocol, direction, ports, action, stats, description), a scrolling log pane, and help text.
- **`events.rs`** — Keyboard event handling: `Q` to quit, `A` to add a rule interactively, `U` to unload the firewall (with confirmation).

## Usage

All commands require root privileges.

### Start the firewall on an interface

```bash
sudo ./target/release/firebee run eth0
```

Optionally load a policy file at startup:

```bash
sudo ./target/release/firebee run eth0 --policy example-policy.yaml
```

### Add rules from a policy file to a running firewall

```bash
sudo ./target/release/firebee add --policy example-policy.yaml
```

To attach to a new interface and load rules in one step:

```bash
sudo ./target/release/firebee add --policy example-policy.yaml --interface eth0 --attach
```

### Launch the TUI

```bash
sudo ./target/release/firebee ui
```

This connects to the already-running firewall's pinned maps and shows live rules, stats, and packet logs.

### Query active rules

```bash
# List all rules (YAML output)
sudo ./target/release/firebee get rule

# Get a specific rule in JSON
sudo ./target/release/firebee get rule block_suspicious_ip --output json
```

### Delete a rule

```bash
sudo ./target/release/firebee delete rule block_suspicious_ip
```

### View and reset statistics

```bash
# Show per-rule stats
sudo ./target/release/firebee stats show

# Reset all counters
sudo ./target/release/firebee stats reset
```

### Cleanup

To fully detach all BPF programs and remove pinned maps:

```bash
sudo ./cleanup.sh
```

## Policy File Format

Rules are defined in YAML (recommended) or JSON. See [POLICY.md](POLICY.md) for the full specification.

### Example (YAML)

```yaml
rules:
  - name: block_suspicious_ip
    ip: 192.168.1.100
    action: drop
    protocol: any
    direction: ingress
    description: Block known malicious IP address

  - name: allow_dns_queries
    ip: 8.8.8.8
    action: allow
    protocol: udp
    dst_port: 53
    direction: both
    description: Allow DNS queries to Google DNS

  - name: block_ssh_from_subnet
    ip: 192.168.100.0/24
    action: drop
    protocol: tcp
    dst_port: 22
    direction: ingress
    description: Block SSH access from entire subnet
```

### Example (IPv6)

```yaml
rules:
  - name: block_google_ipv6_dns_icmp
    ip: 2001:4860:4860::8888/128
    action: drop
    direction: ingress
    protocol: icmp
    description: Block ICMPv6 from Google IPv6 DNS

  - name: allow_cloudflare_ipv6_https
    ip: 2606:4700::/32
    action: allow
    direction: ingress
    protocol: tcp
    src_port: 443
    description: Allow HTTPS from Cloudflare IPv6
```

### Rule Fields

| Field | Required | Default | Values |
|-------|----------|---------|--------|
| `name` | yes | — | Unique identifier |
| `ip` | yes | — | IPv4/IPv6 address or CIDR (e.g. `10.0.0.0/8`, `2001:db8::/32`) |
| `action` | yes | — | `allow` / `pass` / `accept` / `drop` / `deny` / `block` |
| `protocol` | no | `any` | `tcp` / `udp` / `icmp` / `any` |
| `direction` | no | `ingress` | `ingress` / `egress` / `both` |
| `src_port` | no | any | Source port number |
| `dst_port` | no | any | Destination port number |
| `description` | no | — | Human-readable description |

## Testing

```bash
# Run userspace unit tests
make test

# Run BPF kernel-side tests (requires root)
sudo make run_bpf_tests

# Run all tests
sudo make test_all
```


## License

The license will be added in the future.

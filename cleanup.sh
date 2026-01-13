#!/bin/bash

# Detach XDP programs from all interfaces
for iface in $(ip link show | grep -E "^[0-9]+:" | awk -F': ' '{print $2}' | cut -d'@' -f1); do
    # Try to detach XDP program
    sudo ip link set dev "$iface" xdp off 2>/dev/null
done

# Cleanup TC filters and qdisc from all interfaces
for iface in $(ip link show | grep -E "^[0-9]+:" | awk -F': ' '{print $2}' | cut -d'@' -f1); do
    # Remove TC egress filter
    sudo tc filter del dev "$iface" egress 2>/dev/null
    # Remove clsact qdisc
    sudo tc qdisc del dev "$iface" clsact 2>/dev/null
done

# Remove pinned BPF programs and maps
sudo rm -rf /sys/fs/bpf/firebee 2>/dev/null

# Remove maps that might be pinned to root bpf directory
sudo rm -f /sys/fs/bpf/rules_map 2>/dev/null
sudo rm -f /sys/fs/bpf/rule_metadata_map 2>/dev/null
sudo rm -f /sys/fs/bpf/log_events 2>/dev/null
sudo rm -f /sys/fs/bpf/rule_stats_map 2>/dev/null
sudo rm -f /sys/fs/bpf/rules_index 2>/dev/null
sudo rm -f /sys/fs/bpf/xdp_firewall 2>/dev/null
sudo rm -f /sys/fs/bpf/tc_egress_firewall 2>/dev/null

echo "Cleaned up"



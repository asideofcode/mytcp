#!/usr/bin/env bash
# Create/configure tap0 for the mytcp stack (host side = 10.0.0.1/24).
set -euo pipefail

IFACE="${1:-tap0}"
HOST_IP="${2:-10.0.0.1/24}"

if ! ip link show "$IFACE" >/dev/null 2>&1; then
  ip tuntap add dev "$IFACE" mode tap
fi

# Quiet IPv6 ND/RS noise on this learning TAP (IPv4-only stack).
if [[ -w "/proc/sys/net/ipv6/conf/$IFACE/disable_ipv6" ]]; then
  echo 1 > "/proc/sys/net/ipv6/conf/$IFACE/disable_ipv6"
fi

ip addr flush dev "$IFACE" 2>/dev/null || true
ip addr add "$HOST_IP" dev "$IFACE"
ip link set "$IFACE" up
echo "ok: $IFACE up with $HOST_IP (stack should claim the .2 on that /24)"

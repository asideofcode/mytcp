#!/usr/bin/env bash
# Live TAP smoke test — run inside Linux (e.g. Docker with NET_ADMIN).
set -euo pipefail
cd "$(dirname "$0")/.."

go build -o /tmp/mytcp ./cmd/mytcp

ip link del tap0 2>/dev/null || true
ip tuntap add dev tap0 mode tap
if [[ -w /proc/sys/net/ipv6/conf/tap0/disable_ipv6 ]]; then
  echo 1 > /proc/sys/net/ipv6/conf/tap0/disable_ipv6
fi
ip addr add 10.0.0.1/24 dev tap0
ip link set tap0 up

# --- HTTP (default app) ---
/tmp/mytcp -i tap0 -app http -dump=false >/tmp/mytcp.log 2>&1 &
pid=$!
trap 'kill $pid 2>/dev/null || true; ip link del tap0 2>/dev/null || true' EXIT
sleep 0.4

ping -c 3 -W 1 10.0.0.2
curl -fsS --max-time 2 http://10.0.0.2/ | grep -q mytcp
echo "http smoke ok"
kill $pid
wait $pid 2>/dev/null || true
sleep 0.2

# --- HTTPS stdlib (crypto/tls) ---
/tmp/mytcp -i tap0 -app https -dump=false >/tmp/mytcp.log 2>&1 &
pid=$!
sleep 0.5
curl -kfsS --max-time 5 https://10.0.0.2/ | grep -q mytcp
echo "https smoke ok"
kill $pid
wait $pid 2>/dev/null || true
sleep 0.2

# --- HTTPS DIY (mintls TLS 1.2) ---
/tmp/mytcp -i tap0 -app https-diy -dump=false >/tmp/mytcp.log 2>&1 &
pid=$!
sleep 0.5
curl -kfsS --tlsv1.2 --tls-max 1.2 --max-time 5 https://10.0.0.2/ | grep -q mytcp
echo "https-diy smoke ok"
kill $pid
wait $pid 2>/dev/null || true
sleep 0.2

# --- Echo ---
/tmp/mytcp -i tap0 -app echo -tcp 7 -dump=false >/tmp/mytcp.log 2>&1 &
pid=$!
sleep 0.4
printf 'hello-from-smoke\n' | nc -q1 -w2 10.0.0.2 7 | grep -q hello-from-smoke
echo "echo smoke ok"
echo "smoke ok"

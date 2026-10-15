#!/usr/bin/env bash
# Only creates namespaces and interfaces inside them; no host routes/firewall/NAT.
set -euo pipefail
[[ $(uname -s) == Linux && $EUID == 0 ]] || { echo 'Requires root in a disposable Linux CI runner/VM'; exit 1; }
if [[ ${CONNECT_LAB_PERF:-0} == 1 ]]; then
  [[ ${GITHUB_ACTIONS:-} == true && ${CONNECT_DISPOSABLE_PERF:-} == 1 ]] || { echo 'Performance shaping is restricted to disposable CI'; exit 1; }
  command -v tc >/dev/null; command -v iperf3 >/dev/null
fi
for cmd in ip python3 tcpdump sysctl; do command -v "$cmd" >/dev/null; done
root=$(cd "$(dirname "$0")/.." && pwd)
bin=${CONNECT_LAB_BINARY:-$root/bin/connect-core}
[[ -x $bin ]] || { echo 'Build bin/connect-core first'; exit 1; }
artifacts=${CONNECT_LAB_ARTIFACTS:-$(mktemp -d /tmp/connect-ip-results.XXXXXX)}
mkdir -p "$artifacts"
lab=$(mktemp -d /tmp/connect-ip-keys.XXXXXX)
prefix="ccip-$$"
client="$prefix-c"; edge="$prefix-e"; service="$prefix-s"
pids=(); namespaces=()
cleanup() {
  result=$?
  trap - EXIT INT TERM
  if [[ $result != 0 ]]; then
    for log in services server client capture; do
      [[ ! -f $artifacts/$log.log ]] || cat "$artifacts/$log.log"
    done
  fi
  for ns in "${namespaces[@]}"; do
    # Namespace-owned children only; never search/kill host services.
    while read -r pid; do [[ -z $pid ]] || kill -TERM "$pid" 2>/dev/null || true; done < <(ip netns pids "$ns" 2>/dev/null)
    ip netns del "$ns" 2>/dev/null || true
  done
  for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null || true; done
  # Keys created by this script only, exact mktemp path.
  [[ $lab == /tmp/connect-ip-keys.* ]] && rm -rf -- "$lab"
  echo "Results: $artifacts"
}
trap cleanup EXIT INT TERM
# init-lab requires a new directory; keep parent owned by this harness.
"$bin" init-lab "$lab/credentials"
for ns in "$client" "$edge" "$service"; do
  ip netns add "$ns"; namespaces+=("$ns")
  ip -n "$ns" link set lo up
  ip netns exec "$ns" sysctl -q -w net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1
done
ip -n "$client" link add cw type veth peer name ew netns "$edge"
ip -n "$client" addr add 192.168.231.2/30 dev cw
ip -n "$edge" addr add 192.168.231.1/30 dev ew
ip -n "$client" link set cw up
ip -n "$edge" link set ew up
ip -n "$edge" link add el type veth peer name sl netns "$service"
ip -n "$edge" addr add 10.232.0.2/24 dev el
ip -n "$service" addr add 10.232.0.1/24 dev sl
ip -n "$service" addr add 10.232.0.9/24 dev sl
ip -n "$edge" link set el up
ip -n "$service" link set sl up
ip -n "$service" route add 10.231.0.2/32 via 10.232.0.2
ip netns exec "$edge" sysctl -q -w net.ipv4.ip_forward=1
ip netns exec "$service" python3 "$root/scripts/ip-lab-services.py" serve >"$artifacts/services.log" 2>&1 &
pids+=("$!")
ip netns exec "$service" python3 "$root/scripts/ip-lab-services.py" ready
if [[ ${CONNECT_LAB_PERF:-0} != 1 ]]; then
  ip netns exec "$client" tcpdump -U -n -i cw -w "$artifacts/underlay.pcap" >"$artifacts/capture.log" 2>&1 &
  capture=$!; pids+=("$capture")
fi
if [[ ${CONNECT_LAB_MANAGED:-0} == 1 ]]; then
  "$root/bin/connect-control" init "$lab/control" "$lab/credentials/ip-server.json"
  printf '%s\n' 'isolated-ci-only-password' | "$root/bin/connect-ui" init "$lab/ui" http://127.0.0.1:17891 "$lab/control/control-token"
  ip netns exec "$edge" "$root/bin/connect-control" serve "$lab/control/control.json" >"$artifacts/server.log" 2>&1 &
  serverpid=$!; pids+=("$serverpid")
  ip netns exec "$edge" "$root/bin/connect-ui" serve "$lab/ui/ui.json" >"$artifacts/panel.log" 2>&1 &
  pids+=("$!")
  ip netns exec "$edge" python3 "$root/scripts/managed-lab-check.py" start
else
  ip netns exec "$edge" "$bin" ip-server "$lab/credentials/ip-server.json" >"$artifacts/server.log" 2>&1 &
  serverpid=$!; pids+=("$serverpid")
fi
wait_interface() {
  for _ in {1..100}; do if ip -n "$1" link show ccip0 >/dev/null 2>&1; then return; fi; sleep 0.05; done
  cat "$artifacts/server.log" "$artifacts/client.log" 2>/dev/null || true
  echo "TUN did not appear in $1"; return 1
}
wait_interface "$edge"
ip -n "$edge" addr add 10.231.0.1/32 dev ccip0
ip -n "$edge" link set ccip0 up
ip -n "$edge" route add 10.231.0.2/32 dev ccip0
ip netns exec "$client" "$bin" ip-client "$lab/credentials/ip-client.json" >"$artifacts/client.log" 2>&1 &
clientpid=$!; pids+=("$clientpid")
wait_interface "$client"
ip -n "$client" addr add 10.231.0.2/32 dev ccip0
ip -n "$client" link set ccip0 up
ip -n "$client" route add 10.232.0.1/32 dev ccip0 src 10.231.0.2
ip -n "$client" route add 10.232.0.9/32 dev ccip0 src 10.231.0.2
if [[ ${CONNECT_LAB_PERF:-0} == 1 ]]; then
  # Explicit private plaintext baseline; these captures are performance evidence,
  # separate from the ordinary lab's encrypted-traffic / leak checks below.
  ip netns exec "$edge" iperf3 -s -B 192.168.231.1 -p 18084 >"$artifacts/iperf-direct.log" 2>&1 & pids+=("$!")
  ip netns exec "$service" iperf3 -s -B 10.232.0.1 -p 18084 >"$artifacts/iperf-vpn.log" 2>&1 & pids+=("$!")
  sleep 1
  for latency in 0 40; do
    ip netns exec "$client" tc qdisc replace dev cw root netem delay "${latency}ms" limit 20000
    ip netns exec "$edge" tc qdisc replace dev ew root netem delay "${latency}ms" limit 20000
    for route in direct vpn; do
      target=192.168.231.1; [[ $route != vpn ]] || target=10.232.0.1
      for direction in upload download; do
        options=(); [[ $direction != download ]] || options+=(-R)
        ip netns exec "$client" timeout 30 iperf3 -4 -c "$target" -p 18084 -P 4 -t 5 -O 1 --connect-timeout 10000 -J "${options[@]}" >"$artifacts/${route}-${latency}-${direction}.json"
      done
    done
  done
  python3 - "$artifacts" <<'PY'
import json,pathlib,sys
p=pathlib.Path(sys.argv[1]);rows=[]
for f in sorted(p.glob('*-*-*.json')):
    if not f.stem.startswith(('direct-','vpn-')): continue
    d=json.loads(f.read_text());mode,delay,direction=f.stem.split('-')
    rows.append(dict(mode=mode,added_rtt_ms=int(delay)*2,direction=direction,mbps=d['end']['sum_received']['bits_per_second']/1e6,retransmits=d['end']['sum_sent'].get('retransmits'),cpu=d['end'].get('cpu_utilization_percent')))
out={'scope':'disposable Linux TUN + QUIC; same shaped underlay; not public VPS/Windows','streams':4,'results':rows}
(p/'throughput-summary.json').write_text(json.dumps(out,indent=2));print(json.dumps(out,indent=2))
PY
  exit 0
fi
ip netns exec "$client" python3 "$root/scripts/ip-lab-services.py" check >"$artifacts/measurements.json"
# Route exists but policy must still deny .9.
ip netns exec "$client" python3 "$root/scripts/ip-lab-services.py" denied
# No default route/IPv6 route in client namespace: this is isolation, not a host kill switch.
if ip -n "$client" route get 1.1.1.1 >"$artifacts/internet-route.txt" 2>&1; then echo 'Unexpected internet route'; exit 1; fi
if ip -n "$client" -6 route get 2606:4700:4700::1111 >"$artifacts/ipv6-route.txt" 2>&1; then echo 'Unexpected IPv6 route'; exit 1; fi
if [[ ${CONNECT_LAB_MANAGED:-0} == 1 ]]; then
  ip netns exec "$edge" python3 "$root/scripts/managed-lab-check.py" revoke >"$artifacts/management-check.json"
  # Entire controller process restart, not just its data server.
  kill -INT "$serverpid"
  wait "$serverpid"
  ip netns exec "$edge" "$root/bin/connect-control" serve "$lab/control/control.json" >>"$artifacts/server.log" 2>&1 &
  serverpid=$!; pids+=("$serverpid")
  ip netns exec "$edge" python3 "$root/scripts/managed-lab-check.py" persisted
  if ip netns exec "$client" "$bin" ip-client "$lab/credentials/ip-client.json" >"$artifacts/revoked-client.log" 2>&1; then
    echo 'Revoked client connected after controller restart'; exit 1
  fi
fi
kill -KILL "$serverpid"
wait "$serverpid" 2>/dev/null || true
ip netns exec "$client" python3 "$root/scripts/ip-lab-services.py" failure
kill -INT "$capture"
wait "$capture" 2>/dev/null || true
tcpdump -nn -r "$artifacts/underlay.pcap" '(udp port 53) or (tcp port 18080) or (tcp port 18083) or (udp port 18082)' >"$artifacts/plaintext-leaks.txt" 2>/dev/null
[[ ! -s $artifacts/plaintext-leaks.txt ]] || { echo 'Plaintext traffic leaked'; exit 1; }
python3 - "$artifacts/underlay.pcap" <<'PY'
import sys
data = open(sys.argv[1], 'rb').read()
assert len(data) > 24, 'empty capture'
assert b'CONNECT-IP-LAB-PRIVATE-CANARY-2026' not in data, 'plaintext canary leaked'
assert b'\x07example\x04test' not in data, 'DNS query leaked'
PY
cat "$artifacts/measurements.json"
echo 'Real TUN: HTTP, binary TCP, UDP, DNS, policy, endpoint failure and isolated underlay capture passed'

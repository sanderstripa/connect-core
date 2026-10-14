#!/bin/sh
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
# Bind control to the actual UART after devtmpfs replaces the exported /dev.
# PID1's inherited console input is not a reliable bidirectional control channel.
exec </dev/ttyS0 >/dev/ttyS0 2>&1
stty -echo -icanon min 1 time 0
mkdir -p /run /artifacts /dev/net
grep -q 'connect_lab_vm=1' /proc/cmdline || { echo 'LAB_REFUSED'; exec poweroff -f; }
modprobe virtio_pci || true
modprobe virtio_net || true
modprobe tun || true
[ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200
set -eu
nic=$(ls /sys/class/net | grep -v '^lo$' | head -n 1)
[ -n "$nic" ]
ip netns add edge
ip netns add service
ip link set "$nic" netns edge
ip -n edge addr add 10.0.2.15/24 dev "$nic"
ip -n edge link set "$nic" up
for ns in edge service; do
 ip -n "$ns" link set lo up
 ip netns exec "$ns" sysctl -q -w net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1
done
ip -n edge link add el type veth peer name sl netns service
ip -n edge addr add 10.232.0.2/24 dev el
ip -n service addr add 10.232.0.1/24 dev sl
ip -n edge link set el up
ip -n service link set sl up
ip -n service route add 10.231.0.2/32 via 10.232.0.2
ip netns exec edge sysctl -q -w net.ipv4.ip_forward=1
# SLIRP restrict mode drops even replies to forwarded UDP. Enforce isolation in
# the disposable guest instead: no default route and exact default-drop policy.
ip netns exec edge nft -f - <<EOF
table inet connect_lab {
 chain input {
  type filter hook input priority 0; policy drop;
  iifname "$nic" ip saddr 10.0.2.2 ip daddr 10.0.2.15 udp dport 17444 accept
 }
 chain output {
  type filter hook output priority 0; policy drop;
  oifname "$nic" ip saddr 10.0.2.15 ip daddr 10.0.2.2 udp sport 17444 accept
 }
 chain forward {
  type filter hook forward priority 0; policy drop;
  iifname "ccip0" oifname "el" ip saddr 10.231.0.2 ip daddr 10.232.0.1 accept
  iifname "el" oifname "ccip0" ip saddr 10.232.0.1 ip daddr 10.231.0.2 accept
 }
}
EOF
ip netns exec service python3 /services.py serve >/artifacts/services.log 2>&1 &
ip netns exec service python3 /services.py ready
ip netns exec edge tcpdump -U -n -s 160 -i "$nic" -w /artifacts/underlay.pcap >/artifacts/capture.log 2>&1 &
capture=$!
start_server(){
 echo LAB_SERVER_STARTING
 ip netns exec edge /connect-core ip-server /lab/ip-server.json >/artifacts/server.log 2>&1 &
 server=$!
 for i in $(seq 1 200); do
  ip -n edge link show ccip0 >/dev/null 2>&1 && break
  if ! kill -0 "$server" 2>/dev/null; then cat /artifacts/server.log; echo LAB_SERVER_FAILED; exit 1; fi
  sleep .1
 done
 cat /artifacts/server.log
 ip -n edge link show ccip0 || { echo LAB_TUN_TIMEOUT; exit 1; }
 ip -n edge addr add 10.231.0.1/32 dev ccip0
 ip -n edge link set ccip0 up
 ip -n edge route add 10.231.0.2/32 dev ccip0
 ip netns exec edge tcpdump -l -n -i ccip0 >/artifacts/tun-packets.log 2>&1 &
 echo LAB_SERVER_READY
}
start_server
while read -r command; do
 command=$(printf '%s' "$command" | tr -d '\r')
 case "$command" in
  stop-server) kill -KILL "$server"; wait "$server" 2>/dev/null || true; echo LAB_SERVER_STOPPED ;;
  start-server) start_server ;;
  link-down) ip -n edge link set "$nic" down; echo LAB_LINK_DOWN ;;
  link-up) ip -n edge link set "$nic" up; echo LAB_LINK_UP ;;
  diagnostics) cat /artifacts/server.log; cat /artifacts/services.log; cat /artifacts/tun-packets.log; ip -n edge addr; ip -n edge route; ip netns exec edge ss -lun; ip netns exec edge nft list ruleset; echo LAB_DIAGNOSTICS_END ;;
  metrics) python3 - "$server" <<'PY'
import json,os,pathlib,sys
p=pathlib.Path('/proc')/sys.argv[1]
s=(p/'stat').read_text().split(); rss=next(x.split()[1] for x in (p/'status').read_text().splitlines() if x.startswith('VmRSS:'))
print('LAB_LINUX_METRICS '+json.dumps({'cpu_seconds':(int(s[13])+int(s[14]))/os.sysconf('SC_CLK_TCK'),'rss_KiB':int(rss)}),flush=True)
PY
  ;;
  capture) kill -INT "$capture"; wait "$capture" 2>/dev/null || true; echo LAB_PCAP_BEGIN; base64 /artifacts/underlay.pcap; echo LAB_PCAP_END ;;
  shutdown) poweroff -f ;;
 esac
done
while :; do sleep 60; done

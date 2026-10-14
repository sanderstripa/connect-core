#!/usr/bin/env bash
set -euo pipefail
[[ $EUID == 0 && ${CONNECT_LAB_NATIVE_TUN_TEST:-} == 1 ]] || { echo 'Explicit disposable namespace test required'; exit 1; }
root=$(cd "$(dirname "$0")/.." && pwd)
namespace="cc-startup-$$"
ip netns add "$namespace"
trap 'ip netns del "$namespace"' EXIT
ip netns exec "$namespace" sysctl -q -w net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1
ip netns exec "$namespace" env CONNECT_LAB_NATIVE_TUN_TEST=1 "$root/bin/ipvpn-native.test" -test.run '^TestNewNamespaceTUNWritableBeforeHarnessConfiguration$' -test.count=10 -test.v

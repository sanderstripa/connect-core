# Disposable Windows / Linux VM stage

This branch extends the existing CONNECT IP v2 engine. It does not change the
wire format, copy another VPN engine, or grant production deployment permission.
The automated stage is `.github/workflows/vm-pair.yml`. It runs on PR updates.
To reproduce without merging, open the latest paired Actions run for PR #4 and
choose **Re-run all jobs**: Linux image preparation issues fresh disposable
credentials before Windows boots it. Do not rerun just the Windows job with
expired 24-hour provisioning credentials. The workflow_dispatch button may be
unavailable until this workflow exists on the default branch; it is not a reason
to merge automatically. Do not run the network helper on a personal workstation.

## Topology and scope

The client runs in a disposable GitHub Windows VM with official, hash-pinned and
signature-checked Wintun. A second Linux kernel runs in QEMU software emulation
inside that VM. QEMU uses user networking and one loopback UDP port forward.
The guest has no default route and installs default-drop nftables input/output/
forward chains before starting Core, allowing only the exact QUIC peer and
client/service forwarding. SLIRP's `restrict=on` cannot be used here: its
[UDP input implementation](https://raw.githubusercontent.com/qemu/libslirp/master/src/udp.c)
drops guest UDP before looking up a forwarding socket, including QUIC replies.
There is no TAP bridge, Hyper-V configuration, physical host route, VPS,
public listener, or production credential. This is two independent OS kernels,
not two processes pretending to be two machines. It is not an independent
hardware benchmark or a public internet deployment.

QEMU serial control uses a CI-only listener on 127.0.0.1:17445, owned and closed
by the harness; no Core control API is exposed there. The loopback firewall plan
preserves that exact TCP control port. Other endpoint TCP ports remain blocked.
Connected hidden Windows interfaces that cannot be addressed by the helper cause
setup refusal rather than silently weakening service egress guards.
Kernel console and serial evidence use separate UARTs so kernel messages cannot
corrupt packet export. The received PCAP must match the guest's SHA-256 digest;
capture retrieval is repeatable after tcpdump stops.

Linux moves its disposable virtual NIC into an `edge` namespace. A separate
`service` namespace provides HTTP, TCP binary echo, UDP echo and DNS at
10.232.0.1. The client has 10.231.0.2/32; policy permits only 10.232.0.1/32.
Linux kernel forwarding and a return route carry real system packets between
TUN and the services. IPv6, fragments, IP options and broader destinations remain
unsupported and are rejected. There is no internet NAT or default-route VPN.

## Managed client and local control

`connect-core ip-client-managed profile.json` emits JSON-line events on stdout
and accepts commands on inherited stdin. Commands are bounded to 4096 bytes,
reject unknown fields/trailing data, and require `ipc_version: 1`:

```json
{"ipc_version":1,"command":"status"}
{"ipc_version":1,"command":"stop"}
```

Closing the owner pipe stops the client. This interface is intended for a local
CONNECT./CONNECT UI worker; no network management listener is opened. States
include starting, authenticating, ready, reconnecting, failed and stopped. Ready follows
authenticated address assignment and native interface creation.
`ready` describes the engine session; a UI must additionally verify the active
network journal and a tunnel health check before displaying system VPN readiness.
An authenticated
session loss preserves that interface and discards disconnected packets while
retrying fresh mTLS sessions with bounded backoff. Old application packets are
never replayed into a new session. `ip-client-reconnect` exposes the same lifecycle
without pipe commands. This does not promise transparent application recovery.

## Network transaction and crash boundary

`lab-network-windows.ps1` requires administrator privileges, `GITHUB_ACTIONS=true`
and `CONNECT_IP_LAB_VM=1`. These flags are explicit lab gates, not proof of VM
isolation. The helper accepts only the fixed lab address/policy and a newly
created ccip interface. It locks a journal, snapshots interface/DNS/firewall
profile state, and records attempted operations before changing them. Atomic
replacement and flush make interrupted attempts reconcilable.

Persistent outbound guards block IPv6, IPv4 outside the exact endpoint/service,
wrong endpoint TCP/UDP ports and service traffic on inventoried alternate NICs.
Only then are the new interface, /32 route, adapter DNS and `.test` NRPT rule
configured. Guards survive Core process death. Rollback checks interface GUID,
removes only owned changes and removes guards last. Failed rollback must retain
the journal and be treated as an unresolved blocked state. The helper is not a
production Windows Filtering Platform service: adapter hotplug, hostile journal
editing, a reboot recovery service and other privileged network editors are
outside this static disposable lab boundary.

Before declaring the network transaction active, the CI helper journals and
terminates existing external IPv4 TCP flows with the documented Windows
[SetTcpEntry API](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-settcpentry).
This closes the cached-flow reauthorization gap found in a real NIC capture.
Existing external IPv6 flows cause setup refusal. Terminated application sessions
cannot be restored by rollback: only network configuration is restored. This
disruptive operation is restricted to disposable CI VMs and must not be reused
as workstation or production VPN setup.

## Evidence and validation gates

The harness checks actual HTTP, binary TCP/UDP with 1, 8 and 32 concurrent
connections, DNS over the tunnel and the Windows resolver for a unique `.test`
name. It tests bad server identity before interface creation, server kill/restart,
Core crash, blocked direct IPv4/IPv6/DNS probes, and journal rollback. The final
harness also drops/restores the guest virtual NIC with the server process alive;
its result must be verified separately, not inferred from server restart. Unit tests
separately cover wrong CA/client keys, malformed packets and address policies.
Resource artifacts distinguish Windows Core CPU/RAM from Linux Core CPU/RAM.
QEMU emulation overhead means these numbers cannot rank Xray, Sudoku or MIST.

Linux underlay PCAP is automatically checked for endpoint-only encrypted traffic
and absence of the DNS question/plaintext canary in captured 160-byte packet
snapshots. This covers headers and the known UDP/DNS fixture payload prefix;
it is not a byte-for-byte capture of every encrypted payload. The snapshot bound
keeps UART evidence transfer practical under software emulation.
Windows PktMon records complete packets at NIC components and exports each
component separately. Mixed PktMon PCAPNG files lose interface attribution and
even label raw Wintun packets as Ethernet, so they are retained for inspection
but are not used as the leak verdict. The verifier requires native TCP/UDP capture
coverage and checks every alternate NIC for lab IP/canary/DNS bypass, direct
probes, outbound TCP/UDP data and unsupported IPv6 data. Inbound background TCP
data, TCP control packets and IPv6 neighbor discovery are reported separately;
their presence is not absence of transmitted user data. Fragmented/unknown/VLAN
underlay framing causes refusal rather than an unverified pass. A timed-out probe
alone is not proof of no transmitted packet. IPv6 route inventory and exact
socket errors distinguish an unreachable IPv6 path from a filtering verdict.

Result artifacts exclude keys, profiles containing private key paths, vendor
binaries and the boot image. The provisioning image contains disposable 24-hour
lab credentials and has one-day retention; it is never a release artifact.

The first paired data/failure/rollback run passed (Actions 38539058485).
Additional NIC analysis uncovered the existing-flow gap described above; it was
not waived. Final stricter capture verification is recorded separately in
VALIDATION.md. A successful traffic run alone does not prove all leakage gates.

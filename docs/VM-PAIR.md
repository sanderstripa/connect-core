# Disposable Windows / Linux VM stage

This branch extends the existing CONNECT IP v2 engine. It does not change the
wire format, copy another VPN engine, or grant production deployment permission.
The automated stage is `.github/workflows/vm-pair.yml`. Run it from this branch
with GitHub Actions; do not run the network helper on a personal workstation.

## Topology and scope

The client runs in a disposable GitHub Windows VM with official, hash-pinned and
signature-checked Wintun. A second Linux kernel runs in QEMU software emulation
inside that VM. QEMU uses restricted user networking and one loopback UDP port
forward. There is no TAP bridge, Hyper-V configuration, physical host route, VPS,
public listener, or production credential. This is two independent OS kernels,
not two processes pretending to be two machines. It is not an independent
hardware benchmark or a public internet deployment.

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
authenticated address assignment and native interface creation. An authenticated
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

## Evidence and validation gates

The harness checks actual HTTP, binary TCP/UDP with 1, 8 and 32 concurrent
connections, DNS over the tunnel and the Windows resolver for a unique `.test`
name. It tests bad server identity before interface creation, server kill/restart,
Core crash, blocked direct IPv4/IPv6/DNS probes, and journal rollback. Unit tests
separately cover wrong CA/client keys, malformed packets and address policies.
Resource artifacts distinguish Windows Core CPU/RAM from Linux Core CPU/RAM.
QEMU emulation overhead means these numbers cannot rank Xray, Sudoku or MIST.

Linux underlay PCAP is automatically checked for endpoint-only encrypted traffic
and absence of the DNS question/plaintext canary. Windows PktMon ETL/PCAPNG is
collected separately. A timed-out probe alone is not proof of no transmitted
packet. Do not claim complete Windows leakage validation merely from its capture
being present: inspect the capture and state which interfaces were covered.

Result artifacts exclude keys, profiles containing private key paths, vendor
binaries and the boot image. The provisioning image contains disposable 24-hour
lab credentials and has one-day retention; it is never a release artifact.

At creation of this document the paired run is still under investigation. Linux
image preparation and ordinary Windows/Linux checks passed; no cross-VM success,
resource number or complete leak result is claimed until the run and artifacts
are verified. See VALIDATION.md for recorded outcomes.

# CONNECT IP milestone decisions (2026-10-14)

CONNECT is an independent engine and packet protocol, not a cascade of three
engines. The first useful increment transports real IPv4 packets to an isolated
test network. It does not claim a mature, unfilterable, fastest VPN. TLS is its
cryptographic foundation, not its entire application protocol.

## Selected architecture

| Decision | Why / cost / boundary |
| --- | --- |
| QUIC DATAGRAM + reliable control stream | IP packets retain unreliable delivery; avoids TCP-over-TCP retransmission and stream head-of-line blocking. Shared congestion control still couples flows. UDP-blocked paths fail; no automatic TCP fallback. |
| Standard TLS 1.3 mTLS, per-device Ed25519 leaf certificate | Independent device possession proof and CA/name verification, then server certificate fingerprint allowlist. TLS/QUIC handle ephemeral key exchange, directional keys, AEAD, nonces and replay protection. No custom Sudoku/VLESS handshake. |
| Separate CONNECT IP v2 ALPN/header | Own address assignment and packet policy, independent of legacy TCP v1. Not wire-compatible with HTTP CONNECT-IP, Xray, Sudoku or Mist. |
| Server-owned certificate -> IPv4 lease | Client cannot choose another identity/address; one active session per address, duplicate rejected. Server TUN routes reply by destination, not by first/current client. |
| Exact source check + private CIDR policy on both ends | Reject spoofing and unintended forwarding. Client/server policy intersection is effective; no remote hostname resolution or arbitrary proxy destination. Lab permits only private /24 or narrower networks, excludes endpoint and device IP. |
| Inner MTU 1100, outer QUIC 1200, no PMTU discovery | Conservative first IPv4 slice. Drops oversized IP, options, fragments, IPv6, unsupported L4. It cannot carry IPv6's minimum 1280-byte packet yet. Small MTU costs header overhead and packet rate. |
| One TUN, 32 sessions, 64 reply packets per session | No unbounded application delivery queues; a slow client drops packets instead of blocking all reply routing. Application queue payload maximum 32*64*1100 = 2.15 MiB, plus library/socket/read buffers. Limits are not a complete hostile-Internet DoS defense. |
| No engine route/DNS/NAT automation | Linux engine refuses initial network namespace; harness owns ephemeral namespaces. Windows requires explicit isolated-VM opt-in and manual narrow routes. No host-wide kill-switch claim. |
| Keep TCP v1 executable commands/config | Existing lab remains compatible. New CLI `ip-client`/`ip-server` and config version 2 are separate; old profiles never silently become CONNECT IP profiles. |

## Evaluated alternatives

* IP over TCP/TLS: easiest reuse, but loss stalls unrelated packets and nested TCP
  recovery. Retain v1 for regression, do not promote it to default IP VPN.
* IETF MASQUE/CONNECT-IP over HTTP/3: standardized interop, available in current
  Xray/Mist. Extra HTTP/capsule/address-route state and credential semantics.
  Future optional carrier/adapter, not falsely labelled implemented here.
* HTTP/2 fallback / XHTTP: useful when UDP is blocked, but shared reliable
  transport costs and filtering behavior need separate measurements. A transport
  fallback must retain device authentication and explicit policy; no direct path.
* Sudoku table transformation/padding/HTTP mask: potential appearance controls,
  bandwidth and CPU expansion, distinctive statistical behavior, uncertain
  filtering benefit. Separate experiment only after baseline; never encryption.
* VLESS hybrid ML-KEM768+X25519: real current implementation, but transplanting
  its handshake changes trust, replay, licensing and interop risks. Use maintained
  library TLS groups; make no new post-quantum security claim from source reading.
* WireGuard/Noise: a useful reference baseline with audited primitives, but
  would make this a WireGuard adapter rather than define CONNECT's own policy
  protocol. No need to invent a parallel key exchange.
* BBR/Brutal/custom QUIC forks: may improve specific paths, may harm fairness;
  keep maintained quic-go default congestion control before identical-path tests.

## Threat model and security claims

An on-path observer can see endpoints, UDP/QUIC, timing, sizes and dedicated ALPN
in the TLS ClientHello. This milestone supplies no censorship camouflage.
Tampering and replay protection come from TLS 1.3/QUIC packet protection and
packet-number handling; 0-RTT and TLS tickets are disabled. This is reliance on
standard protocols/maintained implementations, not a formal proof or independent
audit of CONNECT's composition. Device certificates must be independently issued.
Compromised CA, client/server key or OS is outside what the tunnel can repair.
Private address bindings cannot substitute for certificate proof.

Authorized clients can reach only configured destination CIDRs through this
engine. They can still consume CPU/bandwidth or flood permitted services: no
public-server DoS hardening, per-device traffic quotas, sandboxed privileged
helper, hot revocation, certificate rotation or persistent management plane yet.
Revocation is configuration update plus restart; active sessions close on engine
shutdown. A certificate is checked at handshake, not continuously revalidated.

The isolated client has no default route and has IPv6 disabled in its namespace.
Captures test absence of plaintext test TCP/UDP/DNS on the underlay and failure
without fallback after server termination. This is evidence for that topology,
not proof of Windows physical-interface, WebRTC or full-device leak protection.

## Acceptance gates

| Area | Required current gate | Next gate before general VPN release |
| --- | --- | --- |
| Correctness | Exact HTTP body, 8 concurrent binary TCP echoes and half-close, 100 UDP echoes, DNS wire response through real TUN | Windows VM -> disposable Linux VM with same fixtures and capture |
| Authentication | Wrong CA/name/client certificate, absent certificate, wrong ALPN, wrong assigned IP rejected | Rotation, expired-during-session, hot revoke closes sessions |
| Policy | Source spoof, unknown destination, malformed IP/control, fragments/IPv6/oversize rejected | Route/DNS/firewall journals, IPv4/IPv6/DNS/WebRTC physical capture in all failure states |
| Stability | Race detection on Windows/Linux; 25 packet-session reconnects, legacy 100 TCP reconnects, cancellation joins handlers | 1h then 24h, 1/8/32 devices, suspend/resume, process crash and memory/goroutine bounds |
| Speed | Record UDP RTT p50/p95/p99; 1MiB echo time and useful payload/time; no Internet speed claim | Identical direct/CONNECT/Mist/Xray/Sudoku baseline with CPU/RAM/drops, MTU and 20/80/200ms RTT, 0/1/3% loss |

Future comparative target: on a documented no-loss lab path, median useful
throughput at least 80% of the matched direct baseline and p95 additional RTT
under 5ms. These are proposed gates, not achieved measurements or guarantees.
Impaired-network and resource budgets require measured baselines first.

## CONNECT. / CONNECT UI integration boundary

CONNECT Core remains a separate executable. A future CONNECT. adapter launches
`ip-client` using a strict v2 profile and reads readiness/stats; elevated route
management must be separate from the UI. Capabilities for this build are
`ipv4/tcp/udp/icmp`, `quic-datagram`, `mtls`, `static-lease`, `isolated-lab`.
They are not `ipv6`, `full-tunnel`, `kill-switch`, `camouflage`, `hot-revoke`.
CONNECT UI can later map device fingerprints to leases and issue profiles, but
no panel/API change or compatibility with existing bearer-token profiles is
claimed. Server policy is a startup snapshot. Existing Xray/Sudoku/Mist profiles
must retain their engine identifiers and pinned executable versions.

## Licensing and code provenance

No Xray, Sudoku or Mist source has been copied or linked into CONNECT Core.
Architectural lessons are implemented independently. Xray is MPL-2.0: modifying
covered files and distributing them entails file-level source obligations.
Upstream Sudoku notices specify GPL-3.0-or-later plus an additional naming/
association restriction; copying/linking it cannot be assumed compatible with
a permissive CONNECT distribution. Have the unusual added condition reviewed
before distribution. Sudoku UI's MIT license does not relicense its patched Core.
MIST UI has an MIT root license but standalone Mist inspected branch has no root
LICENSE: do not assume the UI's license grants rights to standalone engine code.

New dependencies: quic-go MIT, WireGuard-Go TUN MIT, Wintun Go bindings MIT,
Go x/sys/x/net/x/crypto BSD-3-Clause. Pinned versions/checksums are in go.mod/go.sum;
notices are in THIRD-PARTY-NOTICES.md and third_party/licenses. Only the TUN
device package is used, not WireGuard's VPN/Noise engine. Windows needs a separate
official Wintun runtime DLL; it is not included here and has its own distribution
terms. CONNECT Core still has no repository-wide license grant: this milestone
does not invent one on the owner's behalf.

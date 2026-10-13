# Existing implementation audit

Fetched current repository heads and source files during this task. These are
source-level findings, not an audit of the live Amsterdam host or a claim that
every combination works in deployment. No SSH session or server change was made.

| Repository | Inspected revision | Role |
| --- | --- | --- |
| [Connect](https://github.com/sanderstripa/connect) | `ae62014370ff92ea7fe789438bd7d3d0c1fac07e` | Desktop frontend and protocol process orchestration |
| [Mist](https://github.com/sanderstripa/mist/tree/mist-hardening-32) | `mist-hardening-32`, files read live | Private standalone experimental IP transport; main is not the inspected implementation branch |
| [MIST UI](https://github.com/sanderstripa/mist-ui) | `5e55e9a849c338d7f860f63bc03bf25ffe95be87` | Server panel plus modified multi-device Mist engine |
| [Sudoku UI](https://github.com/sanderstripa/sudoku-ui) | `755d6822ac674b65789136e707ba7b222f0b5cc6` | Server panel plus patched upstream Sudoku build |
| [Sudoku desktop](https://github.com/sanderstripa/sudoku-app/blob/main/go.mod) | go.mod read on main | Separate desktop client, dependency `SUDOKU-ASCII/sudoku v0.5.1` |

## Connect

[engines.go](https://github.com/sanderstripa/connect/blob/ae62014370ff92ea7fe789438bd7d3d0c1fac07e/internal/core/engines.go)
selects distinct executables. Xray receives `run -config`; Mist receives `-config`
and a loopback `-socks` argument. Sudoku is configured separately.
[runtime_config.go](https://github.com/sanderstripa/connect/blob/ae62014370ff92ea7fe789438bd7d3d0c1fac07e/internal/core/runtime_config.go)
builds Sudoku client and HEV TUN-to-SOCKS configurations; the Sudoku transport is
explicitly `tcp`, AEAD defaults to `chacha20-poly1305`, multiplex defaults to `off`.
HTTP mask, tables, padding and pure downlink are independent settings.

The Xray importer supports **VLESS, VMess, Trojan**. It supports transports
TCP/raw, XHTTP (`splithttp` imports normalize to `xhttp`), WebSocket and gRPC.
It handles transport security none, TLS or Reality; TLS sets `allowInsecure:false`.
It preserves XHTTP host/path/mode/extra, VLESS flow/encryption, VMess alterId and
encryption, and Reality public key/short ID/SNI/fingerprint. This is config
construction, not proof that all protocol/transport/security combinations are
accepted by Xray or match a server. In particular, importing `security=none`
must not be mistaken for an encrypted tunnel.

Xray runtime has a loopback SOCKS inbound with UDP enabled, a selected proxy
outbound, and a `freedom` direct outbound for explicit routing rules. HEV supplies
the system TUN conversion. Browser use has a separate helper and state directory;
browser proxy coverage is narrower than a system VPN.

## Xray specifically

[engines.ps1](https://github.com/sanderstripa/connect/blob/ae62014370ff92ea7fe789438bd7d3d0c1fac07e/scripts/engines.ps1)
downloads official **Xray v26.3.27**, verifies a fixed archive SHA-256 and bundles
the executable. It is not embedded through a Go module dependency. An arbitrary
current upstream main should not substitute for that packaged version.

Read both the upstream current XHTTP implementation and the pinned
[v26.3.27 dialer](https://github.com/XTLS/Xray-core/blob/v26.3.27/transport/internet/splithttp/dialer.go).
XHTTP separates streaming and packet-upload modes (`stream-one`, `stream-up`,
`packet-up`), HTTP connection selection, upload batching and connection reuse.
The code selects HTTP/1.1, HTTP/2 or HTTP/3 depending on settings, including ALPN;
Reality affects the selection. XHTTP is a transport, not a standalone cipher,
user-management system or replacement for the proxied protocol.

The [VLESS encoder](https://github.com/XTLS/Xray-core/blob/main/proxy/vless/encoding/encoding.go)
shows request version, user identifier, addons, operation and destination parsing.
Reading this header code alone is not a full security assessment of VLESS or its
new optional encryption modes. CONNECT's prototype simply uses TLS 1.3 mTLS and
does not copy the VLESS authentication model or Reality implementation.

For future compatibility, manage Xray as a pinned subprocess adapter, probe its
version and validate generated configs before launch. Test with the actual
packaged version. Retain upstream licenses if distributing it. Existing profiles
remain explicitly Xray profiles; they do not become CONNECT Protocol profiles.

## Mist and MIST UI

The inspected standalone client supports `auto`, `h3s`, `h3`, `h2`. Its automatic
path tries HTTP/3 lanes, then CONNECT-IP over HTTP/3, then an enabled HTTP/2/TLS
fallback. The TLS configuration sets a TLS 1.3 minimum and verifies server name;
HTTP requests carry bearer tokens. IP forwarding uses TUN/Wintun; neither an
Xray proxy nor a TLS handshake alone is evidence of working Mist packet routing.

Connect vendors Mist based on `d4e7dacf22f9c3f4c5d762883544c102da0c6b49` with its
SOCKS adapter. MIST UI vendors the same basis plus additional changes:
[clientrouter](https://github.com/sanderstripa/mist-ui/blob/5e55e9a849c338d7f860f63bc03bf25ffe95be87/engine/internal/clientrouter/router.go)
dispatches TUN replies to assigned device IPv4 addresses, has bounded delivery
queues and rejects duplicate active registrations. The server checks source
addresses. [security_linux.go](https://github.com/sanderstripa/mist-ui/blob/5e55e9a849c338d7f860f63bc03bf25ffe95be87/engine/cmd/mist-edge/security_linux.go)
checks token policy; `watchAccess` checks continuing permission every 500 ms and
closes disallowed streams. These are different engine copies: pin and test both
ends. The panel currently issues IPv4 /24 profiles and blocks inner IPv6.

## Sudoku UI and Core

The [Core workflow](https://github.com/sanderstripa/sudoku-ui/blob/755d6822ac674b65789136e707ba7b222f0b5cc6/.github/workflows/core-release.yml)
pins official Sudoku commit `4889b53cb35355123bebd40e6c76a9582de7c23d` and applies
the repository's [access-control patch](https://github.com/sanderstripa/sudoku-ui/blob/755d6822ac674b65789136e707ba7b222f0b5cc6/core-patches/access-control.patch).
It adds per-user policy, session closure/accounting and a local Unix API. This is
a compatible patched server build, not a separate original transport designed
by the UI. It differs from the desktop's v0.5.1 dependency and needs interop tests.

Read upstream `internal/tunnel/handshake_kip.go`, `session_keys.go`, `server.go` at
that pinned commit: KIP handshake uses ephemeral X25519, HKDF-SHA256 directional
session keys, a random nonce, timestamp checks and a replay cache. The server
reads `UserHash` from client hello metadata. The identifier derived from
`SHA256(privateKey)[:8]` is useful for accounting but does not itself prove
possession of a distinct device private key. Do not carry this identity assumption
into CONNECT; verify possession via standard mutual TLS certificates instead.
This observation is not a completed exploit assessment of the full Sudoku stack.

## Consequence

Reuse architectural lessons and, where appropriate, compatible subprocess
adapters. Avoid copying three divergent codebases into CONNECT Core. Integrate
the new engine into Connect only after independent client/server tests pass.

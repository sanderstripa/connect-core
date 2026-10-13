# Implementation audit — refreshed 2026-10-14

This audit reads pinned sources, not live VPN servers. No SSH, server service,
certificate, routing, DNS or firewall change was made. The sources below were
cloned/read in this task. Security observations are not formal proofs or an
independent cryptographic audit. Implementation decisions are in DECISIONS.md.

## Source inventory and version correction

| Source | Inspected revision |
| --- | --- |
| XTLS/Xray-core | v26.10.10, 701af60772cda123492f86e383e1fdba066614a9 |
| sanderstripa/connect | ae62014370ff92ea7fe789438bd7d3d0c1fac07e |
| SUDOKU-ASCII/sudoku upstream main | 4889b53cb35355123bebd40e6c76a9582de7c23d |
| sanderstripa/sudoku-ui | 755d6822ac674b65789136e707ba7b222f0b5cc6 |
| sanderstripa/mist, mist-hardening-32 | d4e7dacf22f9c3f4c5d762883544c102da0c6b49 |
| sanderstripa/mist-ui | 13cfd64bde5e22e633c619731e43a1b3d62cec88 |

Official [Xray v26.10.10 release](https://github.com/XTLS/Xray-core/releases/tag/v26.10.10)
and GitHub release API confirm tag, prerelease=true, published_at
2026-10-10T09:22:39Z (14:22:39 Yekaterinburg), commit created
2026-10-10T09:21:07Z. Do not describe this prerelease as a stable release.
The release body contains sponsor/project links, not a detailed change list.
The [official version comparison](https://github.com/XTLS/Xray-core/compare/v26.3.27...v26.10.10)
and pinned source are the change evidence; the API comparison is paginated/capped,
so its returned commit list is not represented as an exhaustive changelog.

The previous audit's research pin was outdated. All current Xray mechanism links
below are fixed to v26.10.10. One old version remains a truthful packaging fact:
[Connect engines.ps1](https://github.com/sanderstripa/connect/blob/ae62014370ff92ea7fe789438bd7d3d0c1fac07e/scripts/engines.ps1)
still downloads v26.3.27 with a fixed checksum. Researching 26.10.10 does NOT
upgrade CONNECT.'s bundled executable or prove all its imported profiles work.
That repository is not modified by this task. A future adapter must probe/version
validate actual binaries and test generated configurations before rollout.

## Xray v26.10.10: mechanisms and changed assumptions

* [XHTTP dialer](https://github.com/XTLS/Xray-core/blob/v26.10.10/transport/internet/splithttp/dialer.go)
  selects HTTP/1.1, HTTP/2 or HTTP/3 (Reality selects H2), reuses HTTP clients/Xmux
  and implements stream-one, stream-up and packet-up. HTTP/3 uses the apernet
  quic-go fork and configurable congestion/ChromeParrot behavior. This is not
  the same library/behavior as CONNECT's maintained quic-go. Historical comparison
  includes upload accounting, cancellation/socket lifetime and race fixes.
  Transport reuse/shaping is separate from authentication/encryption.
* [Native TUN configuration](https://github.com/XTLS/Xray-core/blob/v26.10.10/infra/conf/tun.go)
  and [Windows implementation](https://github.com/XTLS/Xray-core/blob/v26.10.10/proxy/tun/tun_windows.go)
  invalidate the assumption that current Xray necessarily requires an external
  TUN-to-SOCKS engine. CONNECT.'s older packaging still uses HEV, but upstream
  now has native TUN with route/interface/DNS options. Linux DNS-to-gateway and
  Windows autoSystemWfpBlockLeak are explicit platform options, not guarantees
  that an arbitrary profile has no leaks. Windows WFP configuration requires
  routing setup and DNS values for the DNS filter.
* [Windows WFP filters](https://github.com/XTLS/Xray-core/blob/v26.10.10/proxy/tun/tun_windows_wfp.go)
  live in a dynamic WFP session: Windows removes them when the process dies.
  Therefore do not infer a persistent crash-time kill switch from their presence.
  [Outbound binding](https://github.com/XTLS/Xray-core/blob/v26.10.10/proxy/tun/tun_windows_outbound.go)
  handles weak-host-send behavior and restoration. CONNECT should eventually
  adopt the lesson of journaled elevated networking and independent crash-safe
  policy, not copy this code or claim it is implemented now.
* [MASQUE dialer](https://github.com/XTLS/Xray-core/blob/v26.10.10/transport/internet/masque/dialer.go)
  and [proxy](https://github.com/XTLS/Xray-core/blob/v26.10.10/proxy/masque/server.go)
  implement CONNECT-IP/H3 and an H2 carrier. QUIC datagrams, address assignment
  and route/pool policy are relevant comparisons to MIST. CONNECT IP v2 uses raw
  QUIC datagrams with its own bounded control exchange, not HTTP/capsules, and
  cannot speak to these MASQUE endpoints. WARP-specific trust behavior must not
  be generalized to ordinary verified TLS or reused as skip-verification.
* [VLESS encryption client](https://github.com/XTLS/Xray-core/blob/v26.10.10/proxy/vless/encryption/client.go),
  [server](https://github.com/XTLS/Xray-core/blob/v26.10.10/proxy/vless/encryption/server.go),
  [record layer](https://github.com/XTLS/Xray-core/blob/v26.10.10/proxy/vless/encryption/common.go)
  and [config](https://github.com/XTLS/Xray-core/blob/v26.10.10/infra/conf/vless.go)
  show ML-KEM768+X25519, directional AEAD, native/xorpub/random presentation,
  optional 0-RTT/tickets and server replay checks. These are distinct from the
  classic VLESS request header. Standard primitives do not prove the whole
  protocol composition secure. CONNECT does not transplant this handshake,
  tickets or encryption framing. TLS/QUIC owns the key schedule and packet crypto.
* [Outbound security validation](https://github.com/XTLS/Xray-core/blob/v26.10.10/infra/conf/xray.go)
  rejects unencrypted VLESS/Trojan public-address configurations (with private
  address/domain exceptions and encryption/security checks). An old importer
  preserving security=none cannot be assumed accepted by 26.10.10. Even allowed
  private-address plaintext is not encrypted because it passed config validation.
* [REALITY](https://github.com/XTLS/Xray-core/blob/v26.10.10/transport/internet/reality/reality.go)
  integrates uTLS, X25519-derived authentication/HKDF and protocol-specific peer
  certificate checks. Its browser-facing appearance and authentication are
  distinct concerns. It is not a generic flag for TLS, and reading code does not
  certify resistance to current filtering or active probing.
* [Sudoku finalmask](https://github.com/XTLS/Xray-core/blob/v26.10.10/transport/internet/finalmask/sudoku/config.go)
  explicitly describes itself as a pure appearance transform without a standalone
  handshake. Do not confuse it with upstream Sudoku's AEAD/KIP transport. Its
  table/packed byte conversion and UDP validation are masking, not new encryption.
* [Dispatcher](https://github.com/XTLS/Xray-core/blob/v26.10.10/app/dispatcher/default.go),
  [VMess AuthID](https://github.com/XTLS/Xray-core/blob/v26.10.10/proxy/vmess/aead/authid.go)
  and [Trojan framing](https://github.com/XTLS/Xray-core/blob/v26.10.10/proxy/trojan/protocol.go)
  separate routing/handlers from authentication and stream/UDP framing. VMess
  timestamps/replay filters are protocol-specific, not a portable authentication
  library. These boundary lessons, not bytes/code, are used in CONNECT.

## Sudoku upstream versus the user's panel

Current upstream main inspected here is still 4889b53; the user's panel workflow
pins that same commit and applies
[access-control.patch](https://github.com/sanderstripa/sudoku-ui/blob/755d6822ac674b65789136e707ba7b222f0b5cc6/core-patches/access-control.patch).
It adds policy/session accounting and a local Unix API. The panel does not invent
an independent cryptographic protocol. CONNECT.'s desktop depends on v0.5.1;
these source identities must be kept separate and interop verified.

[session_keys.go](https://github.com/SUDOKU-ASCII/sudoku/blob/4889b53cb35355123bebd40e6c76a9582de7c23d/internal/tunnel/session_keys.go),
[handshake_kip.go](https://github.com/SUDOKU-ASCII/sudoku/blob/4889b53cb35355123bebd40e6c76a9582de7c23d/internal/tunnel/handshake_kip.go),
[server.go](https://github.com/SUDOKU-ASCII/sudoku/blob/4889b53cb35355123bebd40e6c76a9582de7c23d/internal/tunnel/server.go)
and early.go show PSK-authenticated record setup, ephemeral X25519, HKDF-SHA256
separate directional keys, timestamp/nonce replay checks, and a distinct early
handshake path. AEAD configuration and table transformation are separate layers.
Tables, padding, HTTP mask and pure/packed downlink are appearance/performance
controls with expansion/CPU costs. No independent security proof is inferred
from combining them with standard primitives.

UserHash is supplied in the client hello; deriving it from private-key bytes on
the client does not prove individual private-key possession on the server.
Knowledge of shared transport credentials and admission to that transport are
not necessarily independent device proof. This is an identity-model caution,
not a completed exploit assessment. CONNECT retains separate mTLS leaf
credentials and pins, then binds a lease to the authenticated leaf. It reuses
the directional-key/replay separation lesson through TLS/QUIC, not Sudoku code,
its private handshake or table-based encryption claims.

## MIST and MIST UI

Pinned standalone [client](https://github.com/sanderstripa/mist/blob/d4e7dacf22f9c3f4c5d762883544c102da0c6b49/cmd/mist-client/main.go)
and h3_stream.go/h2.go support h3s lanes, HTTP/3 CONNECT-IP and enabled H2 fallback.
TLS server-name verification and bearer-token authorization are separate.
TUN/Wintun packet pumps, conservative MTU policy, transport choice and failure
handling are directly useful engineering references. HTTP/3 lanes and H2 carry
IP over reliable streams and have different head-of-line behavior from QUIC
DATAGRAM. Neither a successful handshake nor SOCKS traffic proves full VPN routing.

Current MIST UI revision above contains its modified engine. Inspected
[clientrouter](https://github.com/sanderstripa/mist-ui/blob/13cfd64bde5e22e633c619731e43a1b3d62cec88/engine/internal/clientrouter/router.go)
checks source/address policy, prevents duplicate active leases and routes replies
through bounded per-device queues. These are independently implemented in
CONNECT with stricter IPv4/header/length/checksum/fragment checks. Its
[edge authorization](https://github.com/sanderstripa/mist-ui/blob/13cfd64bde5e22e633c619731e43a1b3d62cec88/engine/cmd/mist-edge/security_linux.go)
uses bearer access policy/static token/verified token paths plus rate limits and
conditional QUIC Retry. Existing engine access watchers are useful revocation
references; CONNECT does not yet implement hot revocation or token-panel interop.
Different bundled engine copies must be pinned on both ends.

## What was actually reused

| Origin | Applied in CONNECT | Not imported/claimed |
| --- | --- | --- |
| Xray | Runtime/policy/transport boundaries; fail-closed explicit capabilities | XHTTP, REALITY, VLESS, BBR/Brutal, native WFP code or old engine binary |
| Sudoku | Distinguish AEAD/key schedule/replay from masking; independent device proof requirement | Sudoku KIP, tables, padding, HTTP mask, early data or GPL code |
| MIST / MIST UI | Native IP path, reliable control versus datagrams, assigned device address, anti-spoofing, bounded reply routing | HTTP/3/MASQUE wire compatibility, H3 lanes, H2 fallback, bearer tokens or engine source |

These are justified architectural mechanisms, not a claim that assembling three
engines creates something automatically superior. Current QUIC/TLS crypto is
provided by maintained libraries. No censorship/speed/security superiority claim
is made without comparable measurements and external review. See DECISIONS.md
for alternatives, licenses, threat model and speed/security/stability gates.

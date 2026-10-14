# CONNECT UI validation report

## Local evidence, 2026-10-14

- Go 1.27.0 Windows: `go test -count=1 ./...` passed, including existing TCP/IP tests.
- `go vet ./...` passed. Three commands compile on Windows and Linux amd64.
- Real loopback QUIC test: actual IPv4 payload transferred to an in-memory packet
  device; counters match 32 bytes; revoke closes live QUIC, denies reconnect,
  denies again after reconstructing the controller from disk and restarting it.
  The packet device is a test fixture, not a real OS TUN. Linux TUN has a separate gate.
- Persistence failure returns error and denies in memory. Tombstone stays hidden
  and denied after loading disk state. Invalid/public network configuration rejected.
- Enrollment tests validate signed CSR/challenge/key matching, trust path, duplicate
  and permanently revoked certificate rejection. Export validates as a real v2
  client config and uses real TLS credentials without exporting a private key.
- Panel/API tests: unauthenticated/wrong-token access, Origin/CSRF, cookie flags,
  expiry/logout, five-attempt limit, Host rebinding, unsupported routes/methods,
  malformed JSON, destructive confirmation, one-use challenge, API version mismatch,
  unavailable core and bearer token isolation.
- Browser smoke passed against actual separate processes with real certificates:
  login/session, rename, light/dark persistence, logs, settings, confirmed revoke,
  390px layout, unavailable-core unknown state, logout, no browser errors.
- Local Windows race execution is unavailable without CGO/C compiler; Linux/Windows
  CI runs `go test -race`, not silently replaced with a non-race test.

## CI gates

The PR workflow runs Windows/Linux tests + race/vet/build, the original isolated
Linux TUN suite, and the new managed TUN suite. The managed suite uses real OS TUN,
real network namespaces, TCP/UDP/DNS payloads and the authenticated panel API. It
checks nonzero byte counters, active revocation, complete controller restart and
certificate rejection after restart. A separate browser job saves both themes.

Published as [PR #3](https://github.com/sanderstripa/connect-core/pull/3), branch
`feat/connect-ui-local-control`, without merging. The complete
[CI run 38466332069](https://github.com/sanderstripa/connect-core/actions/runs/38466332069)
for implementation commit `ffb5d97063e47773a6c84a8a089adc8458000d07` finished successfully:

| Gate | Result |
| --- | --- |
| Linux tests, race, vet, builds, packet/control fuzzing | passed |
| Windows tests, race, vet, builds, packet/control fuzzing | passed |
| Original and managed real Linux TUN TCP/UDP/DNS | passed |
| Active revocation + full controller restart + reconnect rejection | passed |
| Windows native Wintun DNS/QUIC fixture | passed |
| Browser authorization/actions/themes/mobile/offline-state checks | passed |

[Managed TUN artifacts](https://github.com/sanderstripa/connect-core/actions/runs/38466332069/artifacts/11848558130)
contain `management-check.json`, real traffic measurements and underlay capture.
The next test commit `6b4f3a2` additionally proves a trusted-but-unregistered
certificate is denied before enrollment, then accepted immediately after signed
CSR enrollment using the actual exported configuration, without restarting the
server; this test passed locally and is included in subsequent PR CI runs.

An installed panel on Windows does not by itself prove Windows-to-Linux VPN
operation or remote VPS suitability. The original Windows native job used the packet fixture; the managed TUN proof in this baseline was Linux-only. The newer desktop system VPN gate uses native Wintun and an independent Linux kernel guest; consult its actual run result before claiming that gate passed.

## Deliberately unavailable

This baseline report describes the original panel validation. The Windows client
extension adds opt-in CA issuance and QR/client URI import; its current instructions
and network validation gate are documented in apps/windows-core-client/README.md.
Safe automatic Core updates, runtime
logging levels, restoring access to a revoked certificate, long-term traffic
history, public administrative listeners, management of existing external service
processes and host route/firewall/DNS changes are not implemented. The UI exposes
only supported controls or explains their absence. Certificate issuance requires
an external trusted CA and independent device identity verification.

State revocation is local to this managed server. It does not issue an external
PKI CRL or revoke credentials on other servers. Failed disk persistence is reported
as failure: its in-memory denial is not claimed as durable. Local administrators
can replace state files; malicious rollback and distributed revocation need a
separate design. Windows ACL provisioning and remote HTTPS deployment are operator
tasks, not automated by this version.

No live VPS deployment, host routing changes or changes to existing VPN services
were performed. The branch is proposed for review; automatic main merge is disabled.

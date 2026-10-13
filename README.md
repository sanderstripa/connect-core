# CONNECT Core

Experimental network engine, with a separate experimental **CONNECT Protocol**.
Two working paths in the existing Go engine: legacy loopback TCP forwarding and
new **CONNECT IP v2**, an isolated IPv4 TUN lab using QUIC DATAGRAM + TLS 1.3 mTLS.
No custom cipher or cryptographic handshake is implemented. Packet policy,
certificate-bound device addresses and control negotiation are CONNECT's own
protocol; this is not a cascade of Xray/Sudoku/Mist.

```text
application -> TUN -> CONNECT IP/2 + QUIC DATAGRAM/mTLS -> server TUN
            -> isolated Linux routing -> TCP / UDP / DNS test network
```

Run the real TUN slice using [IP lab instructions](docs/IP-LAB.md).
Linux runs only in disposable network namespaces. Real Linux TUN TCP/UDP/DNS and
a native Windows Wintun DNS/QUIC round trip passed in isolated CI. The Windows
native job uses a packet fixture as its server; Windows-VM-to-Linux-VM testing
is a separate required gate. See [validation evidence](docs/VALIDATION.md).
No real VPS was accessed. Amsterdam and the Danish services are untouched.

## CONNECT UI

The separate minimal local panel and protected CONNECT IP v2 control process are
documented in [installation, security and compatibility](docs/CONNECT-UI.md).
`connect-control` owns its real QUIC/TUN server, supports durable hot revocation,
CSR proof enrollment of externally issued client certificates and real counters.
`connect-ui` has scrypt passwords, sessions, CSRF and login rate limits; both
administrative listeners are loopback-only. No data server starts automatically.
See [validation and unavailable capabilities](docs/CONNECT-UI-VALIDATION.md).

## Legacy TCP lab (v1)

```text
HTTP application -> local TCP forwarder -> TLS 1.3 / mTLS
                -> CONNECT server -> allowlisted local HTTP service
```

The v1 commands are a TCP tunnel prototype, not a full-device VPN. They do not install TUN,
alter routes, DNS, firewall, proxy settings or existing services, or contact the
Amsterdam VPN. Numeric loopback addresses are enforced for listeners, remote
server addresses and destination services. External deployment is deliberately
unsupported. There is no direct-network fallback and no censorship-bypass claim.

## Run the vertical chain

Go 1.27.0 is the tested toolchain. QUIC/TUN dependencies are pinned in go.mod/go.sum.
From the repository directory:

```powershell
go test -v ./...
go build -o bin/connect-core.exe ./cmd/connect-core
./bin/connect-core.exe init-lab lab
```

Open three terminals in this directory:

```powershell
# Terminal 1: local HTTP test destination
./bin/connect-core.exe http-lab 127.0.0.1:18080

# Terminal 2: CONNECT server
./bin/connect-core.exe server lab/server.json

# Terminal 3: CONNECT client / local port forwarder
./bin/connect-core.exe client lab/client.json
```

Request `http://127.0.0.1:18081/` in a browser or run:

```powershell
curl.exe --noproxy "*" http://127.0.0.1:18081/
```

Expected body: `CONNECT lab HTTP OK`. Exit each process with Ctrl+C. Linux uses
the same commands with `bin/connect-core` as the executable name. If a port is
occupied, choose another port in the lab JSON files and HTTP command; never stop
an unrelated service. `init-lab` requires a new directory and generates a new
disposable CA and two leaf certificates valid for 24 hours. The CA signing key
is not persisted. These are development credentials; do not use real VPN keys.
On Windows, file modes do not establish a restrictive ACL: keep the lab directory
under your own account and do not treat generated keys as production secrets.

## Security and limits

- TLS 1.3 only, trusted lab CA and verified server name; no `InsecureSkipVerify`.
- A client needs both a CA-valid certificate and an allowlisted SHA-256 leaf
  fingerprint. The identifier is not an authentication substitute.
- Dedicated ALPN `connect-lab/1`; no TLS tickets or early application data.
- One TCP connection per forwarded flow, with TCP/TLS half-close support.
- Service identifiers map to fixed numeric loopback destinations on the server.
  Clients cannot supply arbitrary target addresses or create an open proxy.
- At most 32 handlers per listener; five-second handshake/connect deadlines,
  fifteen-second inactivity deadlines and bounded request length.
- Cancellation closes active frontend connections; idle backend reads are bounded
  by their timeout. A stalled flow cannot run forever.
- Configuration rejects unknown fields, trailing input and unknown schema versions.
- Fingerprint policy is a startup snapshot. Change it and restart the lab server
  to revoke a certificate and close existing flows; hot revocation is not built.

The v1 path has no UDP/TUN/QUIC. The v2 isolated path has IPv4 TUN, TCP/UDP/DNS/ICMP
packets, QUIC datagrams, static device leases and private destination policy.
SOCKS, IPv6, HTTP/2 fallback, masking, reconnecting existing flows, privileged
route/DNS/firewall management, full-device kill switch, runtime adapters and
public/remote administration are **not implemented**. Local CONNECT UI is available
for the managed IP v2 path described above. Other applications' traffic outside
the lab is not covered. Namespace leak tests do not prove system-wide Windows
VPN leak safety. Dependencies/licenses and exact reuse are documented in
[decisions](docs/DECISIONS.md) and [refreshed audit](docs/IMPLEMENTATION-AUDIT.md).

## Checks

```text
go test -count=1 -v ./...
go vet ./...
go test -race -count=1 ./...
go test ./internal/core -run '^$' -fuzz FuzzReadRequest -fuzztime=10s
go test ./internal/core -run '^$' -bench BenchmarkTunnelEcho -benchtime=2s
```

Race detection needs a supported C compiler. CI runs Windows and Linux tests,
race detection, vet and compilation. Tests transfer real HTTP across both client
and server, verify binary payloads and half-close with eight clients, reject
untrusted/expired certificates and unsupported ALPN/services, enforce certificate
allowlists, reject malformed wire input, close sessions on shutdown and complete
100 reconnects. Latency measurements are loopback echo round trips. The benchmark
counts both directions of a 64 KiB echo, excluding handshake; do not interpret it
as internet throughput or a comparison with other protocols.

See [implementation audit](docs/IMPLEMENTATION-AUDIT.md),
[architecture and validation plan](docs/ARCHITECTURE.md), and
[wire format](docs/PROTOCOL.md).

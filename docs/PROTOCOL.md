# CONNECT Protocol: TCP lab v1 and isolated IP v2

CONNECT Core is executable software. CONNECT Protocol is the application-layer
wire format it implements. They have independent versions: JSON `config_version`
is 1 for TCP and 2 for the isolated IP configuration. Wire versions are independent.
The name is not a claim of
compatibility with HTTP CONNECT, CONNECT-IP, VLESS or any other protocol.

## Legacy TCP v1 (unchanged)

This first format runs only inside an authenticated TLS 1.3 connection with
ALPN `connect-lab/1`. Authenticate before parsing an application request.

| Offset | Bytes | Field |
| --- | --- | --- |
| 0 | 4 | ASCII `CCP0` |
| 4 | 1 | Version: `1` |
| 5 | 1 | Operation: `1` = OPEN TCP service |
| 6 | 2 | Service identifier length, unsigned big endian, 1..128 |
| 8 | length | Identifier: ASCII letters, digits, `_`, `-` |

The server validates the header, looks up the identifier in its service allowlist,
and connects to that destination. A request cannot contain a target hostname/IP.
Unknown magic/version/operation, invalid lengths/identifiers and truncated
requests close the connection without a detailed error response.

For a syntactically valid request the server sends exactly two bytes:

| Byte | Meaning |
| --- | --- |
| 0 | Wire version `1` |
| 1 | Status: `0` connected, `1` service denied, `2` destination unavailable |

After success, the remaining TLS application bytes are the unframed, bidirectional
TCP stream. There is exactly one OPEN request per TLS connection. EOF closes only
that direction, allowing the response to finish. A relay error closes both ends.
Do not retry already-delivered bytes automatically.

There are no datagram frames, stream IDs, padding, compression, application
nonces, homemade key exchange or separate application encryption. TLS provides
integrity, confidentiality and peer authentication using its maintained library.
Transport timing/size and endpoint metadata remain observable. A dedicated ALPN
does not camouflage this lab as ordinary browser traffic.

Any future multiplex/datagram version must separately specify bounds, state
transitions, ordering, flow control, half-close, error codes and downgrade rules.
Unknown versions fail closed today; no silent fallback to an older version or
another engine. Publish fixed interoperability vectors before adding a second
implementation. Do not freeze this exploratory format as a production standard.

## CONNECT IP v2 (implemented experimental slice)

Carrier: QUIC v1, TLS 1.3, ALPN `connect-ip/2`, mTLS with server-name/CA verification
and server leaf-certificate SHA-256 client allowlist. Tickets and 0-RTT are
disabled. QUIC DATAGRAM support is required; no version or TCP/direct fallback.
IP v2 does not change TCP v1 framing and is not HTTP CONNECT-IP/MASQUE compatible.

Exactly one client-initiated bidirectional reliable stream negotiates the session.
Client sends a 12-byte request; server sends a 12-byte successful reply:

| Offset | Bytes | Request / response |
| --- | --- | --- |
| 0 | 4 | ASCII `CIP2` (version implicit in magic and ALPN) |
| 4 | 2 | Big endian inner MTU, exactly 1100 (`04 4c`) |
| 6 | 2 | Reserved, both zero |
| 8 | 4 | Request: all zero; reply: certificate-bound assigned IPv4 |

Request vector: `43 49 50 32 04 4c 00 00 00 00 00 00`.
Reply for 10.231.0.2: `43 49 50 32 04 4c 00 00 0a e7 00 02`.
Client verifies exact configured assignment before opening TUN. Server acquires
the unique address lease before replying. Unknown version/MTU/reserved bits,
truncation, duplicate lease or invalid credential closes connection; errors do
not negotiate weaker settings. Handshake/control deadlines are 5s; QUIC has a
3s handshake idle timeout, 15s idle timeout and 5s keepalive. Library timeout
semantics include a handshake total timeout derived from its idle timeout.

The control stream remains open. Any later byte, EOF/reset or connection closure
ends the session and releases its lease. Server close error codes: 0 normal
shutdown, 1 malformed/session/pump failure, 2 application session capacity,
3 duplicate active address. There is no detailed unsuccessful reply body.

After successful exchange each QUIC DATAGRAM payload is exactly one complete
inner IPv4 packet, without additional prefix, stream ID or custom crypto. No
application-level reliable delivery/retransmission: packets may drop or reorder;
inner TCP recovers in its own stack. Shared QUIC congestion control still applies.
QUIC does not retransmit DATAGRAM contents. Replies racing ahead of the reliable
reply may be buffered in the library; the client packet pump starts after it
verifies the assignment. No TUN data is accepted before session authorization.

Packet bounds: 20..1100 bytes, IPv4 IHL 5, valid IPv4 header checksum and exact
total length, nonzero TTL, no reserved flag, fragment offset or MF flag. DF is
allowed. TCP header length, UDP length and minimal ICMP header are checked.
Transport checksums are left to the OS. Other L4 protocols, IP options, fragments,
IPv6, loopback/multicast/link-local/unspecified/global broadcast IPs are denied.
Directed subnet broadcast semantics remain destination-policy administrator
responsibility; the generated fixture uses a single /32 destination.

Client->server requires source equal to authenticated assigned IP and destination
in the configured private CIDRs. Server->client requires destination equal to
that IP and source in the same CIDRs. Client applies equivalent checks; no inner
client-supplied destination hostname is resolved. Server policy permits at most
32 canonical private /24-or-narrower prefixes, excludes endpoint/device IP and
at most 32 certificate/address bindings. One session per device; no cross-device
forwarding. Configuration is strict, at most 64KiB, rejects trailing/unknown data.

Server reads one TUN and dispatches replies by destination to per-device queues
of 64 packets. Overflow drops; slow client never blocks another delivery queue.
Malformed/denied datagrams drop without error reflection. Library datagram
queues are also bounded; exact library bounds are version-specific. Cancellation
closes QUIC, TUN and joins packet workers. An I/O failure ends the session; this
revision has no wire-level resume, hot revocation, retry-of-application-data, padding or
automatic transport fallback. Certificate validity is checked at handshake;
active-session expiry enforcement is a future gate. No camouflage or complete
DoS defense is implied by this format.

The managed client may reconnect with a fresh authenticated v2 session while
retaining its native interface. It drops packets during disconnection and does
not replay application data. This changes local lifecycle behavior, not framing
or cryptographic primitives. Private IPC is specified in [VM-PAIR.md](VM-PAIR.md).

# CONNECT Protocol: lab v1

CONNECT Core is executable software. CONNECT Protocol is the application-layer
wire format it implements. They have independent versions: JSON `config_version`
is currently 1; wire version is independently 1. The name is not a claim of
compatibility with HTTP CONNECT, CONNECT-IP, VLESS or any other protocol.

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

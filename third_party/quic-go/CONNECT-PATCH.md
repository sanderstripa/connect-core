# CONNECT local patch

Base: github.com/quic-go/quic-go v0.62.0, original MIT license retained.
Only packet_packer.go and its regression test differ from upstream Go source.
At most 16 already queued DATAGRAM frames fit into available packet space.
No wait timer, custom wire format, key schedule, cipher, MTU, congestion-control
bypass or retransmission is introduced. RFC 9221 section 5 allows coalescing:
https://www.rfc-editor.org/rfc/rfc9221.html#section-5
A frame not fitting after earlier data remains queued for the next packet.
Oversized-first-frame behavior and independent frame payloads are preserved.
This is a maintained local dependency patch, not an upstream release.

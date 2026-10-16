# Windows access to panels on the VPN server

In 0.2.6 and earlier, the helper created a physical /32 route for the entire
VPN endpoint IP. The persistent Windows Filtering Platform guard allowed only
the CONNECT worker's UDP endpoint traffic outside the tunnel. Browser TCP to
other panels on that same IP consequently hit the physical interface and was
denied (`ERR_NETWORK_ACCESS_DENIED`), even though those services remained up.

0.2.7 selects the pre-tunnel interface before configuring Wintun and sets
Winsock `IP_UNICAST_IF` on each CONNECT UDP transport socket. It no longer
creates the endpoint-wide host route. TCP to the same IP follows the normal
tunnel routes. No general TCP permit, port exception, or server firewall
change is introduced. Existing journal-owned routes from older versions are
still validated and removed during explicit recovery. An existing external
more-specific route is never removed or adopted.

The server protocol and enrollment format are unchanged. A 0.2.6 server does
not require an update for this Windows fix. Services must still listen on
nonconflicting ports and their own server firewall must permit VPN traffic.

Validation includes the socket interface option, unchanged unrelated sockets,
shared mTLS/ALPN/device-IP validation and UDP socket lifetime, a disposable
Windows non-loopback endpoint route regression and fail-closed crash probes,
and the existing cross-kernel native VPN/security suite. The route fixture is
not a successful public-panel login test on a live VPS.

The new reported Fast.com samples (different Danish server) are 150/11,
170/7.8 and 140/12 Mbit/s, idle RTT 99 ms and loaded RTT 185–207 ms. These are
field observations, not a controlled comparison with the earlier server.
Upload remains unresolved. CONNECT currently carries IPv4 over native QUIC
DATAGRAM with mutual TLS; it does not run Xray or Sudoku inside this transport.
Further throughput changes require matched-path bidirectional measurements and
stage/CPU/drop counters, rather than assuming another protocol's speed or a
nearer server's result. This release does not claim a throughput improvement.

For continued upload investigation the Windows diagnostics now also read the
owned Wintun adapter's kernel discard/error counters every 30 seconds, alongside
worker/helper CPU and existing stage timings. These are separate from helper
queue drops and inbound Wintun allocation failures; they do not change routing
or increase buffers. A completed speed test followed by Disconnect preserves
these diagnostics without requiring a new VPS login.

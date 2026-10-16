# 0.2.8 congestion investigation

Field observations: 54/11, 59/12 and 64/7 Mbit/s, RTT 100–101 ms idle,
352–536 ms loaded. Native queue mean 92 ms/max 1.9 s; driver/helper drops
zero. QUIC reported 221 lost of 963752 sent packets (about 0.023 percent).
These are observations, not proof of a single root cause.

Rejected experiments, retained in Git history and CI evidence:
- ACK priority: RTT 80 ms upload 333 -> 255 Mbit/s in one paired run.
- ACK priority + packing: upload 405 -> 315 Mbit/s.
- Packing with original FIFO: upload 373 -> 223 Mbit/s.
Neither scheduler nor custom packing patch is shipped in this candidate.
The original bounded FIFO and one-packet-per-DATAGRAM behavior are retained.

The candidate instead uses the standard paced BBR controller from Xray-core
v26.10.10 and the exact apernet/quic-go revision pinned by that Xray release.
The copied BBR/common sources retain MPL-2.0 and original tests. See
internal/congestion/README.md. TLS 1.3, mTLS, ALPN connect-ip/2, certificate
leases, packet policy, MTU, guard and routing remain. No fixed-rate Brutal,
loss-compensation multiplier, Sudoku cipher or masking layer is enabled.

CI compares immutable 0.2.7 and candidate at RTT 0/80 ms, 40 Mbit/s bottleneck,
and additionally 80 ms RTT with 0.02 percent loss in each direction. The latter
is a controlled impairment inspired by the observed packet-loss fraction; it
is not a reproduction of the user's full network path. Windows tests also
verify both directions with released 0.2.7 peers and retain all original
fail-closed, DNS, crash, recovery and capture checks.

A client-only upgrade interoperates with 0.2.7 servers; sender-side BBR in both
directions requires updating CONNECT on the VPS as well. No active VPS or
primary Windows network is modified by the agent. Public speed improvement
requires a live same-path retest and is not established by CI numbers.

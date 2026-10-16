# 0.2.8 packet efficiency work

Field log supplied 2026-10-16: Windows native egress queue sampled mean
92,237 us, maximum 1,895,180 us; QUIC enqueue sampled mean 110 us;
Wintun write mean 10 us, helper IPC mean 9 us. Driver discards/errors and
helper queue drops are zero in the supplied session. These observations
identify queued egress delay, not the sole proven throughput bottleneck.
Fast.com on the same Danish endpoint reported 54/11, 59/12 and 64/7 Mbit/s,
idle RTT 100–101 ms and loaded RTT 352–536 ms.

Two changes are evaluated against immutable released 0.2.7:

- A bounded TCP ACK lane on native client and server egress, with at most eight
  ACKs before bulk service. FIFO is preserved within each class. Data-bearing
  packets, SYN/FIN/RST, fragments and invalid IP headers are not classified as
  priority ACKs. Overflow can use the existing bulk queue. No policy bypass.
- A small local patch to pinned quic-go v0.62.0 packs up to 16 already queued
  standard DATAGRAM frames into available QUIC packet space. No batching timer.
  Subsequent frames that do not fit stay queued. TLS, congestion control, frame
  payloads, packet MTU, mTLS, access control and CONNECT ALPN are unchanged.

The second change reduces packetization overhead for small feedback packets
without inventing a new encrypted envelope or requiring a peer wire upgrade.
RFC 9221 section 5 permits frame coalescing. Original QUIC packer and transport
tests run in CI in addition to CONNECT tests and real disposable VPN tests.

The protocol remains CONNECT IPv4 over QUIC/mTLS. Xray's Sudoku finalmask is
a presentation transform, while upstream Sudoku has its own PSK/session key
schedule. No upstream handshake, cipher composition or obfuscation is copied
or claimed implemented here. Bundling those mechanisms does not by itself
remove the measured queue delay or establish filtering resistance.

Sources inspected: XTLS/Xray-core v26.10.10 transport/internet/finalmask/sudoku/
config.go; SUDOKU-ASCII/sudoku 4889b53 internal/tunnel/session_keys.go;
https://www.rfc-editor.org/rfc/rfc9221.html#section-5

A client-only upgrade works with 0.2.7 servers; symmetric server ACK scheduling
and packet packing require updating the CONNECT server as well. No active VPS
or primary Windows routes/DNS/firewall are changed by this investigation.
Public throughput improvement must be measured on the user's live path after
release; disposable CI figures are not substituted for those measurements.

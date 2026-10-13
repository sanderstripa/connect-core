# Validation evidence

This file is updated with concrete run results for the IP milestone. Until a
result is recorded, an added test or workflow is a prepared check, not a pass.

Local environment: Windows amd64, Go 1.27.0. No WSL Linux installation exists.
The managed shell's socket restrictions blocked ordinary loopback tests; the
same tests passed outside that restriction without changing routes/services.

* Existing TCP v1 tests passed locally, including real HTTP and binary traffic.
* New QUIC/IP tests passed locally: real encrypted UDP transport using an in-memory
  packet device (not Wintun), exact bidirectional bytes, server spoof/destination
  rejection, duplicate address refusal, wrong CA/name/missing certificate/ALPN,
  unexpected assignment, 25 reconnects and server shutdown.
* Windows command built; Linux command cross-compiled. Neither proves live TUN.
* Linux real-TUN namespace workflow and Windows/Linux race/fuzz CI added; final
  run links/results and namespace measurements are recorded after execution.

No Windows Wintun live test, Windows->Linux VM/VPS session, impaired-network
comparison, 24h soak, host-wide kill switch or physical Windows leak test has run.
No server deployment or existing CONNECT./CONNECT UI update has occurred.

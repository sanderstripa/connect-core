# Validation evidence — CONNECT IP milestone

All four jobs passed for code revision
`08fc5c44052c64bc6460ec43dd9647c431ae64e5`:
[CI run 38459666780](https://github.com/sanderstripa/connect-core/actions/runs/38459666780).
This is the source revision with the current transport and test fixes; later
report/documentation commits do not replace this evidence with a claimed pass.

| Job | Verified behavior |
| --- | --- |
| test (ubuntu-latest) | Full v1/v2 tests, race detector, vet, build, packet/control fuzzing and real TCP fixture self-check |
| test (windows-latest) | Same regression/race/vet/build/fuzz/fixture checks; ordinary runs skip privileged TUN creation |
| ip-lab | Two real Linux TUNs in separate namespaces, QUIC/mTLS between them, Linux forwarding to a third service namespace, HTTP/binary TCP/UDP/DNS, denial and crash/no-fallback capture checks |
| windows-tun | Opted-in disposable Windows CI VM: signed/pinned official Wintun 0.14.1, real adapter and narrow /32 route; OS UDP/53 -> Wintun -> QUIC/mTLS -> packet fixture -> Wintun -> OS DNS response; compiled with race detector, passed in 7.48s |

The Windows native server side is a packet fixture, not a Linux kernel. Linux
kernel routing is independently covered by ip-lab. These two passed jobs do not
prove a single Windows->Linux VM/VPS connection. That remains the next gate.
No host-wide route/DNS/firewall change, remote VPS session or production update
was performed. Temporary Windows network changes occurred only on the opted-in,
one-use CI VM and only its newly created adapter.

## Linux measurements (same run)

Ubuntu 24.04.5 amd64 hosted CI, Go 1.27.0, veth underlay, inner MTU 1100;
no added netem impairment. 100 sequential UDP echoes, 8 simultaneous 64KiB TCP
echoes, then 1MiB TCP echo with concurrent send/receive. TCP time includes
connection, full echo and half-close; throughput counts one useful payload,
not both echo directions. HTTP and a real UDP/53 DNS wire question/answer pass.

| Measurement | Value |
| --- | --- |
| UDP RTT p50 | 0.317538 ms |
| UDP RTT p95 | 0.385830 ms |
| UDP RTT p99 | 0.404684 ms |
| 1MiB binary TCP echo | 0.040266974 s |
| Useful 1MiB / echo completion time | 24.83424754 MiB/s |
| Slowest of eight concurrent 64KiB echoes | 0.026765661 s |

These are small, environment-specific smoke measurements, not Internet speed,
one-way link throughput, CPU efficiency, a soak result or superiority to another
protocol. Direct baseline and identical-path Xray/Sudoku/Mist comparisons have
not run. Earlier clean runs produced different figures, as expected on hosted CI.

## Capture and artifacts

[Artifact 11845635141](https://github.com/sanderstripa/connect-core/actions/runs/38459666780/artifacts/11845635141)
contains measurements.json, logs, underlay.pcap and route/leak checks. Its ZIP
was independently downloaded and checked against the GitHub digest:
`9c8aa4e7f8e79841c84921b044a324ec607330908773ebd8cd306dac4724adda`.
No certificate private keys are in this archive.

Independent inspection of all 4247 captured Ethernet frames found:

* 4236 UDP frames involving only 192.168.231.1/.2 and CONNECT port 17444;
* 2 ARP frames;
* 9 ICMP unreachable frames after server failure;
* zero other underlay flows, zero plaintext test canary or DNS question.

The CI capture reports zero packets dropped by the kernel. These findings only
cover the captured isolated topology and tested transitions. They do not establish
Windows physical-interface, IPv6/WebRTC, sleep/resume or full-device leak safety.

## Local checks and failures corrected

Local Windows amd64, Go 1.27.0: legacy real TCP/HTTP and v2 real QUIC packet tests
passed. Socket restrictions in the managed shell initially blocked loopback;
rerunning with authorized network access passed without changing host networking.
Windows command built and Linux command cross-compiled. No WSL Linux exists here.
Native Windows TUN is exercised in CI only, not installed on the workstation.

Local encrypted loopback datagram benchmark, Intel Xeon E3-1230 V2 3.30GHz:
16944 exchanges, 143572 ns/op, one 1024-byte useful payload per exchange,
7.13 MB/s. Handshake and native TUN are excluded; the number is not comparable
with the Linux TUN fixture's MiB/time metric as a speed ranking.

Added rejection tests cover wrong CA/server name/client certificate, absent
certificate, CA-valid but unpinned leaf, mismatched private key, wrong ALPN,
unexpected address assignment, malformed/truncated control, source spoofing,
forbidden destination, fragments/checksum/length/MTU and cross-device reply
isolation. Lifecycle tests perform 25 packet-session reconnects and legacy 100
TCP reconnects, cancellation and server shutdown. Fuzz targets cover IP/control
parsing on both OSes. Native Linux initial-network-namespace use is rejected.

Actual CI uncovered and corrected: TUN poller registration before attachment,
reverse-DNS dependence in the offline HTTP fixture, fixture startup ordering,
large echo deadlock from sequential send/read, PowerShell native argument
splitting, and Windows IP readiness after creating a new adapter. Linux TUN and
native Windows tests passed after those fixes; no failing stage is labelled passed.

## Outstanding

* Real Windows client -> separate isolated Linux VM (then separately authorized
  test VPS), with captures on both sides.
* Internet routing/NAT, default-route protection, system DNS and independent
  crash-safe Windows kill switch with rollback and physical-interface capture.
* IPv6, IP fragments/options, PMTU, impaired networks/UDP blocking, hot revocation,
  active certificate expiry, 1h/24h stability and full 32-device resource tests.
* HTTP/2/XHTTP/REALITY/Sudoku appearance experiments and actual CONNECT./UI adapters.
* Independent security review and matched performance comparisons.

No Amsterdam/Danish VPS service or real server was accessed or changed.

## Managed client / paired VM branch

`isolated-vm-network-stage`, draft PR #4, adds fresh authenticated reconnects
without native interface replacement, owned QUIC UDP listener cleanup, and private
bounded pipe control. Local `go test -count=1 ./...` passed on Windows after these
changes. Baseline Actions run 38534593178 passed Windows/Linux checks. The managed
recovery test uses a real QUIC listener restarted on the same UDP address and an
in-memory packet device; it proves lifecycle logic, not a VM TUN result.

The new paired workflow builds a real Linux guest image and runs it in restricted
QEMU inside a disposable Windows VM. Image preparation passed. Early paired runs
failed: Docker-exported console placeholders prevented observable serial guest
control, and a cleanup null path initially masked the original timeout. These
are recorded as failures, not successful VPN trials. The corrected run is being
checked; cross-VM data, resource measurements and Windows leakage validation are
not yet claimed. See [VM-PAIR.md](VM-PAIR.md) for the executable stage and limits.

# Server performance report

After updating the server/panel, sign in as usual and open **Диагностика**.
Run the speed tests, then click **Скачать отчёт**. The download captures the
latest history, even if the dialog was opened before the tests. Windows
client 0.2.9 is compatible; updating that client is optional for this feature.

The server samples every two seconds into a bounded in-memory history of
180 entries (approximately six minutes). Restarting the CONNECT server resets
the history. Stopping it retains the final record after all peers are drained.
There is no new listener, external monitoring service or disk log of traffic.

Authenticated endpoints: control `/v1/diagnostics`, panel `/api/diagnostics`.
The existing bearer/host checks, panel login and origin/session protections
apply. The panel limits this response to 4 MiB; other routes retain 1 MiB.
Reports exclude configuration, endpoints, names, device certificate IDs,
passwords, private keys, enrollment links and payloads. Transport session
numbers are local to the process and distinguish reconnects without exporting
device identities. At most 32 current/recent transport records are retained;
closed connections release their QUIC object and preserve scalar final stats.

Interpretation:

- `at` is server UTC, not the workstation clock. Match the full test interval.
- `process_cpu_us` is cumulative OS CPU time for CONNECT control, including
  user and kernel time. Difference divided by wall time gives cores consumed;
  multiply by 100 for percent of one core. It is null if unsupported. This
  avoids interpreting blocked Windows profiler stacks as actual CPU use.
- `server.timings` holds cumulative counts, total sampled microseconds and
  maximum waits. Sampling is one packet in 64. A stage with no observations
  has `mean_us: null`; zero samples are not proof of no waiting. The dialog
  computes mean wait from differences between the last two records. Maxima
  remain cumulative since the server start, not per two-second interval.
- `server_send_queue` is the server-to-client application queue; `quic_send`
  measures waiting inside SendDatagram; `receive_queue` and `tun_write` cover
  the client-to-server path. These are local timings, not Internet RTT.
- Transport counters include outer QUIC packets and bytes; packet loss is
  reported by QUIC and can decrease after late acknowledgements. RTT and loss
  are from the server perspective. Separate sessions must not be subtracted
  from one another. A disconnected record retains its own final timestamp.
- Local drops distinguish policy rejection from queue overflow. Their counts
  are not equivalent to underlay packet loss.

The report is a measurement aid, not a claimed throughput fix. Congestion
control, encryption, MTU, routes, DNS, firewall and third-party VPN services
are unchanged. No live production host is modified by CI.

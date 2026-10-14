# Windows / CONNECT UI / VM integration

Integration PR: https://github.com/sanderstripa/connect-core/pull/5

Base main: `8c4bab88cac8a8a857bf8705ca129915c61c90fb`.
Source heads: PR #2 `aebca1d3d9f5e5e4677cb7a18d44de0160776647`,
PR #3 `a06365fcb84c8f17483b139ad8d4dd8d1e9545f2`,
PR #4 `7742e9d820a2e48893c3b04ec5ca36fbb7642030`.

PR #3 is already an ancestor of PR #2. Its panel, broker, protected control
process, installer and tests are retained once. PR #4 is merged into the same
integration branch; CLI dispatch retains import-link/init-enrollment-lab and
ip-client-managed/ip-client-reconnect. The shared guest retains desktop TUN
diagnostics, underlay capture, default-drop policy and separate console channel.
Windows worker/helper code and protocol validation from PR #2 are unchanged.

The desktop binary IPC and managed CLI JSON-lines IPC are separate interfaces.
The CI-only route/DNS/firewall journal helper is not substituted for the desktop
WFP helper. Both test suites remain required. The wire protocol stays CONNECT
IP v2 / QUIC DATAGRAM / TLS 1.3 mTLS, with certificate-bound device addresses.

## Required evidence

The PR checks, not old reports, determine the status of the final integration SHA:

- lab-checks: Windows/Linux race tests, vet, binaries, fuzzing, real Linux TUN,
  managed server/revocation, native Windows TUN, Chromium panel and disposable
  systemd installer/update/rollback/uninstall with neighboring-resource checks.
- Windows Core Client: native C++/Go x64 build, signed/checksummed Wintun,
  desktop smoke, real system IPv4 routing/DNS/WFP against a Linux guest,
  server loss, worker/helper crash, explicit recovery and fresh reconnect,
  physical Windows NIC and Linux underlay capture analysis.
- isolated-windows-linux-vm-pair: managed CLI retained TUN, server restart,
  virtual link loss/recovery, wrong identities, malformed transport, Core
  crash, private IPC, real metrics, capture verification and owned rollback.

TestCurrentPanelQRApprovalAndProtectedResume additionally exercises current
panel HTTPS invitation and PNG QR import, local key persistence/resume,
fingerprint approval, DPAPI storage, and the exact exported managed-vps profile
against PR #4's owned listener and managed engine with real encrypted loopback
packet exchange. It uses in-memory devices, not host Wintun. Missing local DNS
is explicitly refused before the desktop network helper starts.

Request schemas carry token/CSR only. Client keys stay local; broker approval
issues a matching certificate. Existing tests cover key/token absence from
server state, foreign-key/replay refusal, restart, expiry, cancellation and
durable revocation. Export references client-local key paths; it does not
transfer a private key from the server. Windows import accepts these paths
and current invitations; managed VPS profiles request a local numeric DNS
through the native dialog, without manual JSON editing.

Historical documents describe their original branches and narrower fixtures.
They are not evidence that the integrated head passed, nor production claims.
Download final-head artifacts only after all required jobs finish successfully.

## Remaining limits

IPv4 only. Desktop system mode blocks IPv6 outside loopback; IPv6 tunneling is
absent. Public Internet throughput, independent physical machines, adverse
network/UDP-blocking behavior, long-duration load and production VPS field
operation remain unverified. Reconnect establishes new authenticated sessions;
it does not restore existing TCP flows transparently. Persistent deny rules
after helper/worker crashes are not proof of boot-time isolation. Reboot,
power-loss windows, privileged interference and rollback failure need separate
testing. QR reads PNG/JPEG files; camera capture and Windows URL association
are not implemented. This is not production-ready certification.

## Safe next test on a separate VPS

Do not install this on an existing VPN server or run system mode on the main
Windows machine. Use a fresh disposable Linux systemd VPS with a snapshot and
provider console, plus a separate disposable Windows VM. Keep their credentials
and networking independent of Amsterdam, Xray, Sudoku and MIST.

1. Record the reviewed final PR head's full 40-character SHA and obtain its
   matching Windows x64 artifact. Verify ZIP/executable checksums and Wintun
   signature. Fetch scripts/install-vps.sh from that exact SHA, inspect it,
   then run `sudo bash install-vps.sh install --revision FULL_REVIEWED_SHA` on
   the disposable VPS only. Do not use the wrapper's default channel: it still
   resolves PR #3's branch. Review the displayed plan before confirming.
2. Supply a separate test panel password. Review discovered IPv4, unused ports,
   private /24 and uplink; use explicit overrides from VPS-INSTALL.md where
   needed. Permit only selected data UDP and enrollment TCP ports in the
   provider firewall. Keep administration on loopback through an SSH tunnel.
3. Start the matching panel, create a new invitation, import the link or its
   PNG/JPEG on the Windows VM, independently compare full key fingerprints,
   and approve. Retain no real user keys. Select a numeric tunnel DNS in the
   client's native prompt; use the VPS/network's intended DNS, never infer it
   from the data endpoint.
4. Capture every Windows physical NIC and VPS underlay before connecting.
   Use controlled HTTP/TCP/UDP/DNS destinations and unique payload/DNS canaries.
   Verify server-observed IPv4 egress, system DNS, TLS identity, counters,
   concurrency and packet policy. Explicitly test DNS-over-TCP separately.
5. Stop only this test server, interrupt the VM uplink, crash only this worker
   and helper, and inspect failed direct IPv4/DNS/IPv6 probes together with
   captures. Require fresh-session recovery and accurate failed state. A
   timeout alone does not establish leak absence. Preserve all captures.
6. Verify revocation closes the session and survives service restart. Test
   installer update/rollback with state intact, then owned uninstall and the
   final route/DNS/firewall inventory. Save failures; discard the VM/VPS if
   rollback ownership is uncertain. Do not clear global firewall rules.
7. Treat reboot/boot-time isolation, long-duration load and public throughput
   as new gates. Keep the integration unmerged if any required gate is failing
   or evidence remains ambiguous. No live VPS deployment is performed by CI.

See VPS-INSTALL.md for dependencies and installer options, VM-PAIR.md for the
managed laboratory harness, and apps/windows-core-client/README.md for desktop
import, DNS choice, recovery and limitations.

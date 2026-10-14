# CONNECT CORE — native Windows 11 client

Independent C++20 Win32 / Direct2D / DirectWrite interface and a separate Go CONNECT Core worker. The existing CONNECT user application is unchanged. Keep `ConnectCore.exe`, `connect-desktop-core.exe`, `ConnectCoreNetwork.exe` and the official signed `wintun.dll` in the same protected directory. Start the interface as an ordinary user.

## Build and verification

Requires Go 1.27.0, CMake 3.20+, Visual Studio C++ tools and Windows SDK:

```powershell
go test -count=1 ./...
go vet ./...
go build -trimpath -ldflags="-s -w" -o dist/connect-desktop-core.exe ./cmd/connect-desktop-core
cmake -S apps/windows-core-client -B build/desktop -A x64
cmake --build build/desktop --config Release
Copy-Item build/desktop/Release/ConnectCore*.exe dist/
./scripts/desktop-smoke.ps1 -Directory dist
./dist/ConnectCore.exe
```

Obtain Wintun 0.14.1 from its official supplier. The Windows workflow pins the archive SHA256, checks its Authenticode publisher and packages its license. The privileged helper checks its signature again before loading it. Never substitute an unsigned DLL.

The workflow additionally builds an independent Linux kernel guest and exercises the native worker/helper against the real Linux TUN server. This network test is restricted to disposable GitHub Actions Windows machines. It checks TCP, UDP, DNS, concurrency, transport failure, worker failure, recovery and reconnection. Captures from pre-existing Windows network interfaces and the Linux underlay are checked for the controlled plaintext canary and test DNS name. This is evidence for that test scope; it does not certify every network environment. A successful compile or UI smoke test alone does not verify a VPN session.

## Configuration and access

The configuration button accepts the current CONNECT IP v2 client JSON, a `connect://` invitation from the clipboard, or a PNG/JPEG containing its QR code. F2 opens import; Ctrl+V imports an invitation. There is no camera capture. JSON imports resolve relative certificate paths against the JSON directory and reject unknown fields, invalid policy, expired/mismatched client credentials and server configurations.

Credentials are stored as a self-contained current-user Windows DPAPI bundle in `%LOCALAPPDATA%/ConnectCoreLab/profile.dpapi`. Its directory has a protected user-only DACL. The original imported files are unchanged; protect those copies yourself. Diagnostics never contain raw keys, invitation tokens, configurations or packet contents.

Invitations from the current CONNECT UI 0.2 panel contain a 15-minute one-use enrollment token, an HTTPS origin and its public certificate. They contain no device private key. The Windows worker generates an Ed25519 key locally and stores its key and signed CSR as a DPAPI-protected pending record before contacting the service. Only the signed CSR is submitted. The window displays both halves of the complete SHA256 public-key fingerprint, which can also be copied through safe diagnostics. Compare it with the panel before the administrator approves the device.

The panel binds the invitation to exactly one proof/key. Approval issues one certificate; retries with the same proof retrieve the same result rather than create another device or certificate. A different key cannot reuse the token. If the window closes before approval or a response is lost, reopen the same invitation: the client resumes its protected pending identity. On success it checks the certificate against the local key and trusted CA, writes the final DPAPI profile and removes the pending record. TLS 1.3, hostname/lifetime validation and the public certificate carried by the invitation are required; proxies and redirects are forbidden. The earlier experimental five-minute SPKI invitation format remains accepted for compatibility.

F9 or `ConnectCore.exe --register-protocol` registers this executable for `connect://` under the current user. An association belonging to another CONNECT application is refused rather than overwritten. Opening a link requires confirmation in the client. `--import <URI>` forwards to the existing client instance when one is already open. Treat an invitation as temporary access authority and share it privately.

## Existing panel and configuration compatibility

The branch integrates the actual CONNECT UI 0.2 broker and approval flow. Use the panel's existing invitation and registration actions; the desktop client does not substitute a second browser access service. Its server-side CA signer remains on the server and never goes to the browser or device. Follow [CONNECT-UI.md](../../docs/CONNECT-UI.md) and [VPS-INSTALL.md](../../docs/VPS-INSTALL.md) for the panel's existing operator configuration. No running VPS is modified by the desktop implementation.

Current v2 profiles with `environment: managed-vps` and their `device_network` are recognized, in addition to isolated laboratory profiles. A panel export intentionally has no Windows-local DNS setting. Before its first system connection, a compact native dialog asks for a numeric IPv4 DNS server reachable through that VPN. There is no guessed DNS or direct resolver fallback. The confirmed local `network` policy is saved with the protected profile. The UI remains explicitly labeled for isolated system VPN trials until native network validation is complete.

## Packet laboratory and system VPN

Without an explicit `network` policy, the original packet-only laboratory behavior applies: no Wintun, elevation, route or DNS changes. The diagnostic packet probe is an actual policy-checked UDP IP packet to the first configured destination on port 18082.

System mode requires the explicit optional v2 policy:

```json
"destinations": ["0.0.0.0/0"],
"network": {"mode": "system-vpn", "dns": "10.232.0.1"}
```

Use a numeric IPv4 Core endpoint, a valid private device address and a numeric unicast tunnel DNS address. Legacy packet tests require `environment: isolated-lab`; current managed server exports retain their actual `managed-vps` environment and private device pool. System VPN remains visibly designated for isolated trials until the native network test gate passes; production deployment and Internet gateway/NAT configuration are separate operator tasks. No VPS is deployed or changed by this component.

The UI asks for explicit confirmation; only the small network helper requests UAC. It installs persistent Windows Filtering Platform protection, creates its own Wintun adapter, assigns the device address, sets tunnel DNS and installs split default IPv4 routes. IPv6 outside loopback is blocked, not tunneled. A narrowly scoped endpoint exception allows only the Core worker's UDP transport. The interface and network worker never run as administrator.

A failed handshake or lost server leaves protection active. There is no implicit direct-network fallback. Explicit disconnect removes the client's own adapter/routes and removes its filters last. If the helper or worker crashes, protection persists. F10, or the diagnostic recovery button, requests UAC for recovery of the client's journaled network state. Recovery refuses an active helper and never removes arbitrary adapters, routes or another application's filters. This intentionally can leave connectivity blocked after a crash until recovery is requested.

## Status, metrics and lifecycle

Connected means successful real Core negotiation and, in system mode, successful helper network setup. Traffic totals and rates count successfully sent/accepted inner IP bytes, excluding QUIC/TLS overhead. Session totals reset on a new connection. The system-mode diagnostic DNS probe uses the configured tunnel DNS and bound device address, with no alternate resolver or direct fallback. Its actual measured RTT is labeled as DNS latency; other unavailable latency is shown as unavailable.

F6 opens diagnostics; F8 changes the saved light/dark theme. Space connects/disconnects and Escape disconnects. The window scrolls at high DPI. Safe logs can be copied explicitly.

The interface launches exactly one worker into a kill-on-close Job Object using private anonymous pipes and an inherited-handle allowlist. IPC has magic CC, version 2, typed commands with bounded payloads, and fixed 176-byte status frames. Unknown operations, versions and invalid/truncated lengths close IPC. The privileged helper uses a random local named pipe with restricted ACL and verifies the sponsor process; the worker verifies the elevated helper identity. Neither command lines nor helper plans contain device keys. The helper exists only for a system-mode session or explicit recovery. No background service or startup task is installed.

# CONNECT CORE — Windows 11 laboratory client

Independent C++20 Win32 / Direct2D / DirectWrite UI and a separate Go Core worker.
No existing CONNECT user application is modified. Start `ConnectCore.exe` with
`connect-desktop-core.exe` beside it. Runs as the ordinary user; no installation,
browser runtime, service, startup task, administrator token or Wintun is needed.

## Build

Requires Go 1.27.0, CMake 3.20+, Visual Studio 2022 C++ tools and Windows SDK:

```powershell
go test -count=1 ./...
go vet ./...
go build -trimpath -ldflags="-s -w" -o dist/connect-desktop-core.exe ./cmd/connect-desktop-core
cmake -S apps/windows-core-client -B build/desktop -A x64
cmake --build build/desktop --config Release
Copy-Item build/desktop/Release/ConnectCore.exe dist/
./scripts/desktop-smoke.ps1 -Directory dist
./dist/ConnectCore.exe
```

CI builds both executables and uploads `ConnectCore-Windows-x64`. No Wintun DLL
is distributed by this component. Theme follows the saved explicit selection.

## Import and test

Use **+ Конфигурация** to import the existing `ip-client.json` format from
`connect-core init-lab <new-directory>` (config_version 2, isolated-lab), including
endpoint, interface, device_ip, destinations and nested trust fields. Relative
certificate paths resolve against the JSON directory. All existing Core policy
restrictions apply. Certificates and private key must match, be currently valid
and trusted for client authentication. Server name verification remains enabled.
Server configuration and unknown JSON fields are rejected. The source JSON/key
files are not modified: protect or remove your original copies yourself.

Import stores a self-contained credential bundle encrypted with current-user
Windows DPAPI in `%LOCALAPPDATA%/ConnectCoreLab/profile.dpapi`; the directory has
a protected current-user-only DACL. The worker uses decrypted bytes in memory;
it creates no plaintext credential files. Delete the directory to forget the
profile. Diagnostics use fixed messages, never raw configuration, TLS errors,
paths, packet contents or keys. Clipboard copying is explicitly requested.

**Подключить** asks for explicit laboratory confirmation and calls the real
`ipvpn.Dial`: QUIC v1, CONNECT IP/2 control negotiation, TLS 1.3 mTLS and validation
of the certificate-bound device lease. Connected means that negotiation succeeded;
it does not assert application reachability or a full-device VPN. Server loss
closes the packet pump and changes the state to failure. There is no reconnect
or direct fallback. Disconnect cancels and joins the pump. No application traffic
is captured, forwarded or redirected, no interface is created and no system
routes, DNS, proxy or firewall settings are changed.

The diagnostics **Отправить IP-пробу** button injects one real policy-checked UDP
IPv4 packet into `ipvpn.Client` via a bounded application-owned packet device.
It targets the first destination prefix's address on UDP port 18082 (lab echo
fixture). Use a /32 destination for a fixture; a /24 may name its network address.
Run a real isolated Core server and echo fixture as described in
[IP-LAB.md](../../docs/IP-LAB.md). Replies received through Core are counted.
No reply is fabricated and receipt is not interpreted as an echo validation.

Rates are deltas of successfully sent/accepted inner IP bytes, sampled every
500 ms. They exclude QUIC/TLS overhead and all computer traffic outside this
session. Session totals persist on disconnect and reset on the next connect.
Latency is explicitly **Недоступна**; no handshake duration is mislabeled RTT.

## Process and IPC security

One Go process exists while the window is open. UI uses an absolute adjacent
worker path, an explicit inherited-handle allowlist and private anonymous pipes.
Commands have magic CC, version 1, a typed operation and little-endian bounded
length (32 KiB); status is a fixed 160-byte payload. Unknown operations, invalid
versions, oversized/truncated frames and unexpected command payloads close IPC.
There is no TCP listener, named pipe namespace or command-line secret. UI parses
only fixed-size status frames. The worker starts suspended and must join a
kill-on-close Job Object before execution. Pipe EOF requests graceful shutdown;
UI waits at most six seconds before terminating its own job. Job closure also
reclaims the worker if the UI crashes. Keep the executable directory protected
from other users; current-user malware is outside the IPC/DPAPI boundary.

## Explicit limits / next gate

This MVP is a **packet-only laboratory client**, not an OS VPN. It does not
provide Wintun or route operations, so no privileged helper is shipped and no
elevation is requested. A separate, reviewed minimal UAC helper plus disposable
Windows/Linux VM tests is required before enabling system networking. Do not
enable the entire UI as administrator. No public endpoint support, full-device
kill switch, latency probe, automatic fixture startup or packaged VPN claim.

CI smoke checks native window creation, theme hit areas, one worker and graceful
exit. Unit tests cover bounded IPC and real existing Core packet/crypto/session
behavior. Visual DPI review, manual import dialogs and Windows-to-Linux fixture
tests remain separate checks; green compilation is not evidence of those checks.

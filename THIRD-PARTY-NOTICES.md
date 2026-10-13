# Third-party notices

Pinned sources and checksums are recorded in go.mod/go.sum. License texts:

- quic-go v0.62.0: MIT, quic-go contributors, third_party/licenses/quic-go-MIT.txt.
- WireGuard-Go TUN package ecfc5a8d5446: MIT, WireGuard LLC, third_party/licenses/wireguard-go-MIT.txt.
- Wintun Go bindings 0fa3db229ce2: MIT, WireGuard LLC, third_party/licenses/wintun-bindings-MIT.txt.
- Go x/crypto v0.54.0, x/net v0.56.0, x/sys v0.47.0: BSD-3-Clause, The Go Authors; corresponding x-*-BSD.txt texts.

Only the Windows TUN device binding is imported from WireGuard-Go; Linux uses
x/sys/unix and a non-offloading native TUN. This does not embed the WireGuard
protocol. Standard library/runtime carry the Go project's license.
Wintun's separately supplied native DLL is not included or relicensed here.

No Xray, Sudoku or Mist source/binary is copied into this repository. Their
research references are not dependency license grants. Test-only transitive
modules appear in go.sum but are not automatically binary runtime dependencies.
This notice is not a repository-wide license for CONNECT Core.

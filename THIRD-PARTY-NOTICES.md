# Third-party notices

Pinned sources and checksums are recorded in go.mod/go.sum. License texts:

- quic-go v0.62.0: MIT, quic-go contributors, third_party/licenses/quic-go-MIT.txt.
- WireGuard-Go TUN package ecfc5a8d5446: MIT, WireGuard LLC, third_party/licenses/wireguard-go-MIT.txt.
- Wintun Go bindings 0fa3db229ce2: MIT, WireGuard LLC, third_party/licenses/wintun-bindings-MIT.txt.
- Go x/crypto v0.54.0, x/net v0.56.0, x/sys v0.47.0: BSD-3-Clause, The Go Authors; corresponding x-*-BSD.txt texts.
- go-winio v0.6.2: MIT, Microsoft; third_party/licenses/go-winio-MIT.txt.
- go-qrcode da1b6568686e: MIT, Tom Harwood; third_party/licenses/go-qrcode-MIT.txt.
- gozxing v0.1.1: MIT, Daisuke MAKIUCHI; third_party/licenses/gozxing-MIT.txt.
- Go x/text v0.40.0 and x/xerrors 5ec99f83aff1: BSD-3-Clause, The Go Authors; corresponding x-text-BSD.txt and x-xerrors-BSD.txt texts.

Only the Windows TUN device binding is imported from WireGuard-Go; Linux uses
x/sys/unix and a non-offloading native TUN. This does not embed the WireGuard
protocol. Standard library/runtime carry the Go project's license.
The Windows desktop artifact additionally distributes the official signed
Wintun 0.14.1 native DLL under its supplier's terms, with WINTUN-LICENSE.txt.
It is downloaded from the supplier with a pinned checksum and publisher check;
the repository does not relicense that binary.

No Xray, Sudoku or Mist source/binary is copied into this repository. Their
research references are not dependency license grants. Test-only transitive
modules appear in go.sum but are not automatically binary runtime dependencies.
This notice is not a repository-wide license for CONNECT Core.

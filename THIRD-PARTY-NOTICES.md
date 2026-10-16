# Third-party notices

Pinned sources and checksums are recorded in go.mod/go.sum. License texts:

- apernet/quic-go 184d081eef3e: MIT, quic-go and apernet contributors,
  third_party/licenses/apernet-quic-go-MIT.txt. This is the exact fork revision
  pinned by Xray-core v26.10.10, without a local packet-packing patch.
- Xray-core v26.10.10 BBR/common congestion sources: MPL-2.0,
  internal/congestion/MPL-2.0.txt and third_party/licenses/xray-BBR-MPL2.txt.
  Original source and tests are provided under internal/congestion with only
  package import paths adapted. Authentication, proxy and masking are not copied.
- uTLS v1.8.2: BSD-3-Clause; Brotli v1.0.6: MIT; klauspost/compress v1.17.4:
  BSD-3-Clause. Corresponding license texts are in third_party/licenses.
- WireGuard-Go TUN package ecfc5a8d5446: MIT, WireGuard LLC, third_party/licenses/wireguard-go-MIT.txt.
- Wintun Go bindings 0fa3db229ce2: MIT, WireGuard LLC, third_party/licenses/wintun-bindings-MIT.txt.
- Go x/crypto v0.57.0, x/net v0.59.0, x/sys v0.48.0: BSD-3-Clause, The Go Authors; corresponding x-*-BSD.txt texts.
- go-winio v0.6.2: MIT, Microsoft; third_party/licenses/go-winio-MIT.txt.
- go-qrcode da1b6568686e: MIT, Tom Harwood; third_party/licenses/go-qrcode-MIT.txt.
- gozxing v0.1.1: MIT, Daisuke MAKIUCHI; third_party/licenses/gozxing-MIT.txt.
- Go x/text v0.42.0 and x/xerrors 04be3eba64a2: BSD-3-Clause, The Go Authors; corresponding x-text-BSD.txt and x-xerrors-BSD.txt texts.

Only the Windows TUN device binding is imported from WireGuard-Go; Linux uses
x/sys/unix and a non-offloading native TUN. This does not embed the WireGuard
protocol. Standard library/runtime carry the Go project's license.
The Windows desktop artifact additionally distributes the official signed
Wintun 0.14.1 native DLL under its supplier's terms, with WINTUN-LICENSE.txt.
It is downloaded from the supplier with a pinned checksum and publisher check;
the repository does not relicense that binary.

Only the attributed Xray BBR/common congestion source is included. No Xray
proxy, Sudoku or Mist engine is embedded. Test-only transitive
modules appear in go.sum but are not automatically binary runtime dependencies.
This notice is not a repository-wide license for CONNECT Core.

Public IP certificate issuance uses lego v5.5.2 (MIT). Its imported ACME runtime
also includes backoff/v5 v5.0.3 (MIT), go-jose/v4 v4.1.5 (Apache-2.0),
miekg/dns v1.1.73 (BSD-3-Clause) and go-pkcs12 v0.7.3 (BSD-3-Clause).
Corresponding license texts are in third_party/licenses. DNS provider SDKs and
lego's standalone CLI are not imported or included in the CONNECT binaries.

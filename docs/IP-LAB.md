# Isolated CONNECT IP lab

## Verified versus prepared

This milestone adds real packet transport and native TUN implementations, with
Linux namespace CI and Windows/Linux packet/crypto tests. See VALIDATION.md for
actual run evidence. A Windows Wintun implementation compiling is not proof of
Windows -> Linux device connectivity. No VPS has been accessed or modified.

## Linux: complete vertical test

Use a disposable Ubuntu VM/CI runner with Go 1.27, Python 3, iproute2 and tcpdump.
No SSH credentials are needed. Build as the ordinary user, run harness as root:

```sh
go test -race -count=1 ./...
go build -o bin/connect-core ./cmd/connect-core
sudo env CONNECT_LAB_ARTIFACTS="$PWD/ip-lab-artifacts" bash scripts/ip-lab-linux.sh
```

The harness creates three uniquely named network namespaces:

```text
client app -> ccip0 (10.231.0.2, MTU 1100)
           -> CONNECT IP/2 QUIC + mTLS over private veth (192.168.231.2 -> .1:17444)
           -> edge ccip0 -> Linux IPv4 forwarding
           -> service namespace 10.232.0.1: HTTP / TCP echo / UDP echo / DNS
```

Underlay and service links are created directly inside namespaces. There is no
host bridge, host route, default route, NAT, host firewall change or host sysctl
change. The harness enables forwarding only in the edge namespace and disables
IPv6 only in its namespaces. It adds narrow lab routes, uses new disposable
24-hour certificates and removes its namespaces/keys on exit, including failure.
If a required interface or namespace cannot be created it exits; it never stops
an unrelated service. Linux engine refuses the initial network namespace.

Artifacts contain measurements.json, process logs, underlay.pcap and leak/route
checks. They contain no certificate private keys. Capture can include public TLS
metadata/certificates. Server is deliberately killed to test endpoint failure.
The default artifacts path is printed; CI uploads artifacts on success/failure.
The CLI writes only aggregate packet counts at exit, not packet contents/keys.

DNS test sends an actual UDP/53 question for example.test to a fixture and verifies
the response address. It is not system-resolver configuration or public DNS/NAT.
The `.9` fixture also answers UDP, ensuring deny tests cannot pass merely because
there is no service. Invalid/oversized/IPv6 packets are dropped, never sent direct.

## Windows -> isolated Linux VM: prepared manual stage

This stage requires two disposable VMs on a private virtual switch with no
production services and no Internet gateway. The procedure is not executed on
the user's Windows workstation or any VPS in this milestone.

1. Linux VM: build Core, create a new lab directory with `init-lab`. Run the edge
   inside a new network namespace with private underlay address
   192.168.231.1:17444 and service network 10.232.0.1/32, using the same edge/service
   routes as the harness. Attach only the dedicated lab vNIC to that namespace.
   Do not move an existing production vNIC into it. Start `ip-server` and fixtures.
2. Windows VM: build `go build -o bin/connect-core.exe ./cmd/connect-core`. Obtain
   Wintun DLL from the official [Wintun site](https://www.wintun.net/), verify the
   supplier's signature/hash, use the correct architecture, place it next to the
   executable. No DLL/driver installer is supplied here. Copy only ca.pem,
   client.pem and client.key from the disposable lab over the isolated VM channel;
   never copy the server key. Protect the files with the VM user's ACL.
3. Rewrite `trust.ca`, `trust.cert`, `trust.key` in ip-client.json to the Windows
   absolute paths. Set endpoint 192.168.231.1:17444, device_ip 10.231.0.2,
   destinations `["10.232.0.1/32"]`, interface ccip0 and config_version 2.
   The certificate server_name remains localhost for these lab certs, despite
   dialing a private IP. Do not replace name validation with skip-verification.
4. In the isolated Windows VM only, use an elevated terminal:

```powershell
$env:CONNECT_IP_LAB_VM='1'
.\bin\connect-core.exe ip-client .\ip-client.json
```

5. Once it reports ready, configure just that new Wintun interface in a second
   elevated terminal in the disposable VM:

```powershell
$labInterface = Get-NetAdapter -Name ccip0
New-NetIPAddress -InterfaceIndex $labInterface.ifIndex -IPAddress 10.231.0.2 -PrefixLength 32
New-NetRoute -InterfaceIndex $labInterface.ifIndex -DestinationPrefix '10.232.0.1/32' -NextHop 0.0.0.0
```

6. Run `python scripts/ip-lab-services.py check` in the Windows VM. Capture the
   dedicated lab vNIC with Wireshark, test bad certificates and stopping Linux
   Core; verify no plaintext UDP/53, TCP test traffic, DNS question or canary on
   the vNIC. Check the VM has no alternate gateway/default route, disable IPv6
   on its disposable vNIC or use a switch that cannot carry IPv6 outside the lab.
   The engine itself does not configure Windows IPv6 or a kill switch.
7. Stop Core; delete only the added /32 route and IP if still present, using the
   captured interface index. Remove the disposable VM/snapshot afterwards.

CONNECT_IP_LAB_VM is an explicit opt-in, not a VM detector/sandbox. This manual
test is a required next gate; no Windows Wintun or cross-OS live success is inferred
from CI compilation. Public endpoint addresses and broad destination routes are
intentionally rejected. Moving to a separately authorized test VPS requires a
new reviewed deployment stage, real credential issuance, endpoint route protection,
rollback and an explicit server-change approval. Amsterdam and the Danish VPS
remain outside this lab.

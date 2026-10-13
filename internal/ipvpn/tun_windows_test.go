package ipvpn

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"testing"
	"time"
)

// Explicit opt-in on an ephemeral GitHub Windows VM only. Ordinary test runs
// never create adapters, install drivers or modify the workstation's networking.
func TestWindowsNativeTUNQUICDNS(t *testing.T) {
	if os.Getenv("CONNECT_IP_LAB_NATIVE_TEST") != "1" || os.Getenv("GITHUB_ACTIONS") != "true" {
		t.Skip("native TUN test requires an opted-in disposable GitHub Windows VM")
	}
	t.Setenv("CONNECT_IP_LAB_VM", "1")
	f := setup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	c, e := Dial(ctx, f.address, f.tls, netip.MustParseAddr("10.231.0.2"))
	if e != nil {
		t.Fatal(e)
	}
	defer c.CloseWithError(0, "test")
	name := fmt.Sprintf("ccipw-%d", os.Getpid())
	d, e := Open(name)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	cleanup := fmt.Sprintf(`$a=Get-NetAdapter -Name '%s' -ErrorAction SilentlyContinue; if($a){Get-NetRoute -InterfaceIndex $a.ifIndex -DestinationPrefix '10.232.0.1/32' -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue; Get-NetIPAddress -InterfaceIndex $a.ifIndex -IPAddress '10.231.0.2' -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue}`, name)
	defer func() {
		_, _ = exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", cleanup).CombinedOutput()
	}()
	command := fmt.Sprintf(`$ErrorActionPreference='Stop'; $a=Get-NetAdapter -Name '%s'; Set-NetIPInterface -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -NlMtuBytes 1100 -Dhcp Disabled -DadTransmits 0 -InterfaceMetric 5; New-NetIPAddress -InterfaceIndex $a.ifIndex -IPAddress '10.231.0.2' -PrefixLength 32 -PolicyStore ActiveStore | Out-Null; New-NetRoute -InterfaceIndex $a.ifIndex -DestinationPrefix '10.232.0.1/32' -NextHop '0.0.0.0' -RouteMetric 5 -PolicyStore ActiveStore | Out-Null; for($i=0;$i -lt 100;$i++){ $ip=Get-NetIPAddress -InterfaceIndex $a.ifIndex -IPAddress '10.231.0.2'; if($ip.AddressState -eq 'Preferred'){break}; Start-Sleep -Milliseconds 50 }; Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 | Format-Table IPAddress,AddressState,SkipAsSource | Out-String | Write-Output; Get-NetRoute -InterfaceIndex $a.ifIndex -DestinationPrefix '10.232.0.1/32' | Format-Table DestinationPrefix,NextHop,State | Out-String | Write-Output; if($ip.AddressState -ne 'Preferred'){throw 'New lab address is not ready'}`, name)
	if out, e := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command).CombinedOutput(); e != nil {
		t.Fatalf("configure newly-created test adapter: %v\n%s", e, out)
	} else {
		t.Logf("new adapter configuration: %s", out)
	}
	done := make(chan error, 1)
	stats := &Stats{}
	go func() {
		done <- Client(ctx, c, d, Policy{netip.MustParseAddr("10.231.0.2"), []netip.Prefix{netip.MustParsePrefix("10.232.0.1/32")}}, stats)
	}()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("native Windows pump shutdown stuck")
		}
	}()
	query := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 4, 't', 'e', 's', 't', 0, 0, 1, 0, 1}
	// Server-side packet fixture answers the actual OS-originated DNS request.
	// Linux kernel routing/full TCP are covered by the separate namespace job.
	answerDone := make(chan struct{})
	go func() {
		defer close(answerDone)
		for {
			select {
			case <-ctx.Done():
				return
			case p := <-f.device.write:
				if len(p) < 28 || p[9] != 17 || binary.BigEndian.Uint16(p[22:24]) != 53 || !bytes.Equal(p[28:], query) {
					continue
				}
				payload := append([]byte{}, query...)
				payload[2] = 0x81
				payload[3] = 0x80
				payload[7] = 1
				payload = append(payload, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 10, 232, 0, 1)
				reply := udp("10.232.0.1", "10.231.0.2", payload)
				copy(reply[20:22], p[22:24])
				copy(reply[22:24], p[20:22])
				select {
				case f.device.read <- reply:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	defer func() { cancel(); <-answerDone }()
	sock, e := net.DialUDP("udp4", &net.UDPAddr{IP: net.ParseIP("10.231.0.2")}, &net.UDPAddr{IP: net.ParseIP("10.232.0.1"), Port: 53})
	if e != nil {
		t.Fatal(e)
	}
	defer sock.Close()
	_ = sock.SetDeadline(time.Now().Add(8 * time.Second))
	if _, e = sock.Write(query); e != nil {
		t.Fatal(e)
	}
	b := make([]byte, 512)
	n, e := sock.Read(b)
	if e != nil {
		t.Fatal(e)
	}
	if n != len(query)+16 || !bytes.Equal(b[:2], query[:2]) || !bytes.Equal(b[n-4:n], []byte{10, 232, 0, 1}) {
		t.Fatalf("bad native DNS response: %x", b[:n])
	}
	if stats.Sent.Load() == 0 || stats.Received.Load() == 0 {
		t.Fatal("DNS bypassed packet pumps")
	}
	t.Log("Windows OS UDP/53 -> real Wintun -> QUIC/mTLS -> packet fixture -> Wintun -> OS DNS response passed")
}

package ipvpn

import (
	"os"
	"testing"
)

func TestNewNamespaceTUNWritableBeforeHarnessConfiguration(t *testing.T) {
	if os.Getenv("CONNECT_LAB_NATIVE_TUN_TEST") != "1" {
		t.Skip("requires the disposable namespace startup regression gate")
	}
	device, err := Open("ccrace0")
	if err != nil {
		t.Fatal(err)
	}
	defer device.Close()
	// Model an authenticated reconnect sending before the external harness
	// assigns addresses/routes. The isolated kernel may drop this packet, but
	// must accept the write rather than tear down the whole server with EIO.
	packet := udp("10.231.0.2", "10.232.0.1", []byte("startup-regression"))
	n, err := device.Write(packet)
	if err != nil || n != len(packet) {
		t.Fatalf("new TUN not writable before harness configuration: n=%d err=%v", n, err)
	}
}

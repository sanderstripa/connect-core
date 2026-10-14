package ipvpn

import (
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/unix"
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
	// Confirm the kernel's original failure mode on this exact owned device,
	// rather than merely assuming that the observed disappearing TUN was a race.
	socket, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(socket)
	req, err := unix.NewIfreq("ccrace0")
	if err != nil {
		t.Fatal(err)
	}
	if err = unix.IoctlIfreq(socket, unix.SIOCGIFFLAGS, req); err != nil {
		t.Fatal(err)
	}
	req.SetUint16(req.Uint16() &^ unix.IFF_UP)
	if err = unix.IoctlIfreq(socket, unix.SIOCSIFFLAGS, req); err != nil {
		t.Fatal(err)
	}
	if _, err = device.Write(packet); !errors.Is(err, unix.EIO) {
		t.Fatalf("DOWN TUN did not reproduce the startup failure: %v", err)
	}
	t.Log("owned UP TUN accepts early packet; owned DOWN TUN reproduces EIO")
}

//go:build windows

package main

import (
	"context"
	"golang.org/x/sys/windows"
	"net"
	"testing"
)

// Setting a per-socket interface changes neither host routes nor the firewall.
func TestTransportSocketPinsOnlyItsOwnInterface(t *testing.T) {
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	var index uint32
	for _, i := range interfaces {
		if i.Flags&net.FlagUp != 0 && i.Flags&net.FlagLoopback == 0 {
			index = uint32(i.Index)
			break
		}
	}
	if index == 0 {
		t.Skip("no active underlay")
	}
	lc := underlayListenConfig(index)
	pc, err := lc.ListenPacket(context.Background(), "udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	raw, err := pc.(*net.UDPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var value int
	var optionErr error
	if err = raw.Control(func(fd uintptr) { value, optionErr = windows.GetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, 31) }); err != nil {
		t.Fatal(err)
	}
	if optionErr != nil {
		t.Fatal(optionErr)
	}
	if uint32(value) != index {
		t.Fatalf("socket interface %x, want interface %d (getsockopt returns host order)", value, index)
	}
	// A normal application socket must remain unbound; no IP-wide exception.
	normal, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer normal.Close()
	r, err := normal.(*net.UDPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	r.Control(func(fd uintptr) { value, optionErr = windows.GetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, 31) })
	if optionErr != nil || value != 0 {
		t.Fatalf("unrelated socket changed: %d %v", value, optionErr)
	}
}

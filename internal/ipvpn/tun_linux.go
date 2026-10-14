package ipvpn

import (
	"errors"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// Use a non-offloading TUN: one IPv4 packet per read, no virtio/GSO framing.
// O_NONBLOCK makes os.File.Close unblock an outstanding poll/read on shutdown.
func Open(name string) (Device, error) {
	if e := isolation(); e != nil {
		return nil, e
	}
	return openLinux(name, false)
}

// OpenOwned attaches only the installer's persistent interface, whose kernel
// ownership is checked by TUNSETIFF. It does not create routes or change MTU.
func OpenOwned(name string) (Device, error) {
	if name != "cc-vps0" {
		return nil, errors.New("installer-owned TUN required")
	}
	if _, e := net.InterfaceByName(name); e != nil {
		return nil, e
	}
	return openLinux(name, true)
}
func openLinux(name string, owned bool) (Device, error) {
	fd, e := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if e != nil {
		return nil, e
	}
	fail := func(e error) (Device, error) { _ = unix.Close(fd); return nil, e }
	req, e := unix.NewIfreq(name)
	if e != nil {
		return fail(e)
	}
	flags := uint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if !owned {
		flags |= unix.IFF_TUN_EXCL
	}
	req.SetUint16(flags)
	if e = unix.IoctlIfreq(fd, unix.TUNSETIFF, req); e != nil {
		return fail(e)
	}
	if owned {
		return os.NewFile(uintptr(fd), "connect-owned-tun"), nil
	}
	// Only the interface just created in this disposable namespace is affected.
	socket, e := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if e != nil {
		return fail(e)
	}
	defer unix.Close(socket)
	req.SetUint32(MTU)
	if e = unix.IoctlIfreq(socket, unix.SIOCSIFMTU, req); e != nil {
		return fail(e)
	}
	// A reconnecting peer can send immediately after the server authenticates
	// it. Linux returns EIO when a packet is written to a DOWN TUN, so make our
	// newly created namespace-only device writable before publishing it. Address
	// assignment, routes, DNS and firewall remain the harness's responsibility.
	if e = unix.IoctlIfreq(socket, unix.SIOCGIFFLAGS, req); e != nil {
		return fail(e)
	}
	req.SetUint16(req.Uint16() | unix.IFF_UP)
	if e = unix.IoctlIfreq(socket, unix.SIOCSIFFLAGS, req); e != nil {
		return fail(e)
	}
	// Register with Go's poller only after TUNSETIFF: an unattached /dev/net/tun
	// descriptor cannot yet be polled, causing os.NewFile to disable netpoll.
	return os.NewFile(uintptr(fd), "connect-ip-tun"), nil
}

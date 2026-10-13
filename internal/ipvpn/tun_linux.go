package ipvpn

import (
	"os"

	"golang.org/x/sys/unix"
)

// Use a non-offloading TUN: one IPv4 packet per read, no virtio/GSO framing.
// O_NONBLOCK makes os.File.Close unblock an outstanding poll/read on shutdown.
func Open(name string) (Device, error) {
	if e := isolation(); e != nil {
		return nil, e
	}
	fd, e := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), "connect-ip-tun")
	fail := func(e error) (Device, error) { _ = f.Close(); return nil, e }
	req, e := unix.NewIfreq(name)
	if e != nil {
		return fail(e)
	}
	req.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_TUN_EXCL)
	if e = unix.IoctlIfreq(fd, unix.TUNSETIFF, req); e != nil {
		return fail(e)
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
	return f, nil
}

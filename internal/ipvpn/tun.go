//go:build windows

package ipvpn

import (
	"errors"
	"sync"

	"golang.zx2c4.com/wireguard/tun"
)

type native struct {
	device tun.Device
	once   sync.Once
	err    error
}

func Open(name string) (Device, error) {
	if e := isolation(); e != nil {
		return nil, e
	}
	d, e := tun.CreateTUN(name, MTU)
	if e != nil {
		return nil, e
	}
	go func() {
		for range d.Events() {
		}
	}() // Drain platform notifications.
	return &native{device: d}, nil
}
func (d *native) Read(b []byte) (int, error) {
	sizes := []int{0}
	n, e := d.device.Read([][]byte{b}, sizes, 0)
	if e != nil {
		return 0, e
	}
	if n != 1 {
		return 0, errors.New("TUN returned no packet")
	}
	return sizes[0], nil
}
func (d *native) Write(b []byte) (int, error) {
	n, e := d.device.Write([][]byte{b}, 0)
	if e != nil {
		return 0, e
	}
	if n != 1 {
		return 0, errors.New("TUN short packet write")
	}
	return len(b), nil
}
func (d *native) Close() error { d.once.Do(func() { d.err = d.device.Close() }); return d.err }

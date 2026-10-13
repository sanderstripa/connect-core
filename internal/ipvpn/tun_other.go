//go:build !linux && !windows

package ipvpn

func Open(name string) (Device, error) { return nil, isolation() }

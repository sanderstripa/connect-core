//go:build !linux

package ipvpn

import "net"

func activatedPacketConn(string) (net.PacketConn, error) { return nil, nil }

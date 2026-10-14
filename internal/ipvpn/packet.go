// Package ipvpn implements CONNECT IP v2; cryptography is delegated to TLS/QUIC.
package ipvpn

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

const MTU = 1100 // Fits QUIC DATAGRAM on the mandatory 1200-byte QUIC path.
const ALPN = "connect-ip/2"

// Packet rejects fragments, options and IPv6 rather than silently bypassing policy.
func Packet(p []byte) (src, dst netip.Addr, err error) {
	if len(p) < 20 || len(p) > MTU || p[0] != 0x45 || int(binary.BigEndian.Uint16(p[2:4])) != len(p) {
		return src, dst, errors.New("invalid IPv4 length/header")
	}
	if binary.BigEndian.Uint16(p[6:8])&0xbfff != 0 || p[8] == 0 {
		return src, dst, errors.New("fragment/reserved flag/TTL")
	}
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(p[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	if sum != 65535 {
		return src, dst, errors.New("IPv4 checksum")
	}
	switch p[9] {
	case 6:
		if len(p) < 40 || int(p[32]>>4)*4 < 20 || 20+int(p[32]>>4)*4 > len(p) {
			return src, dst, errors.New("TCP header")
		}
	case 17:
		if len(p) < 28 || int(binary.BigEndian.Uint16(p[24:26])) != len(p)-20 {
			return src, dst, errors.New("UDP length")
		}
	case 1:
		if len(p) < 28 {
			return src, dst, errors.New("ICMP header")
		}
	default:
		return src, dst, errors.New("unsupported IP protocol")
	}
	src = netip.AddrFrom4([4]byte(p[12:16]))
	dst = netip.AddrFrom4([4]byte(p[16:20]))
	if !unicast(src) || !unicast(dst) {
		return src, dst, errors.New("non-unicast address")
	}
	return src, dst, nil
}
func unicast(ip netip.Addr) bool {
	return ip.Is4() && !ip.IsUnspecified() && !ip.IsLoopback() && !ip.IsMulticast() && !ip.IsLinkLocalUnicast() && ip != netip.MustParseAddr("255.255.255.255")
}

type Policy struct {
	Device       netip.Addr
	Destinations []netip.Prefix
}

func (p Policy) Allows(packet []byte, fromDevice bool) bool {
	src, dst, err := Packet(packet)
	if err != nil {
		return false
	}
	remote := src
	if fromDevice {
		if src != p.Device {
			return false
		}
		remote = dst
	} else if dst != p.Device {
		return false
	}
	if remote == p.Device {
		return false
	}
	for _, prefix := range p.Destinations {
		if prefix.Contains(remote) {
			// Internet policy does not grant access to private networks/metadata.
			if prefix.Bits() == 0 && (remote.IsPrivate() || !remote.IsGlobalUnicast() || netip.MustParsePrefix("100.64.0.0/10").Contains(remote) || netip.MustParsePrefix("0.0.0.0/8").Contains(remote)) {
				return false
			}
			return true
		}
	}
	return false
}

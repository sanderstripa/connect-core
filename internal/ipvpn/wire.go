package ipvpn

import (
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
)

// Fixed-size, reliable session negotiation. No allocation from peer lengths.
func hello(w io.Writer, ip netip.Addr) error {
	var h [12]byte
	copy(h[:4], "CIP2")
	binary.BigEndian.PutUint16(h[4:6], MTU)
	if ip.IsValid() {
		a := ip.As4()
		copy(h[8:], a[:])
	}
	for b := h[:]; len(b) > 0; {
		n, e := w.Write(b)
		if e != nil {
			return e
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
func readHello(r io.Reader, server bool) (netip.Addr, error) {
	var h [12]byte
	if _, e := io.ReadFull(r, h[:]); e != nil {
		return netip.Addr{}, e
	}
	if string(h[:4]) != "CIP2" || binary.BigEndian.Uint16(h[4:6]) != MTU || h[6] != 0 || h[7] != 0 {
		return netip.Addr{}, errors.New("unsupported IP protocol/MTU")
	}
	ip := netip.AddrFrom4([4]byte(h[8:12]))
	if server && !ip.IsUnspecified() || !server && !unicast(ip) {
		return netip.Addr{}, errors.New("invalid assignment")
	}
	return ip, nil
}

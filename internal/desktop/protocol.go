// Package desktop is the bounded, versioned IPC contract of the laboratory client.
package desktop

import (
	"encoding/binary"
	"errors"
	"io"
)

const Version = 2
const MaxPayload = 32768
const (
	Import           byte = 1
	Connect          byte = 2
	Disconnect       byte = 3
	Probe            byte = 4
	Exit             byte = 5
	ImportURI        byte = 6
	ImportQR         byte = 7
	Recover          byte = 8
	ConfigureDNS     byte = 9
	ConfigureNetwork byte = 32
	FromTUN          byte = 33
	ToTUN            byte = 34
	NetworkCounters  byte = 35
	Status           byte = 128
)
const (
	Idle uint32 = iota
	Ready
	Connecting
	Connected
	Failed
	Enrolling = 6
)

// Status: state/code, TX/RX/elapsed, mode, bounded identifier[128], DNS RTT.
// The state discriminates the identifier: Enrolling carries a public-key SHA256
// fingerprint, all other states carry the selected Core endpoint. Neither carries
// an invitation token or private material.
const StatusSize = 176

func Read(r io.Reader) (byte, []byte, error) {
	var h [8]byte
	if _, e := io.ReadFull(r, h[:]); e != nil {
		return 0, nil, e
	}
	n := binary.LittleEndian.Uint32(h[4:])
	if h[0] != 'C' || h[1] != 'C' || h[2] != Version || n > MaxPayload {
		return 0, nil, errors.New("invalid IPC frame")
	}
	b := make([]byte, n)
	_, e := io.ReadFull(r, b)
	return h[3], b, e
}
func Write(w io.Writer, kind byte, b []byte) error {
	if len(b) > MaxPayload {
		return errors.New("oversized IPC frame")
	}
	h := []byte{'C', 'C', Version, kind, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(h[4:], uint32(len(b)))
	for _, p := range [][]byte{h, b} {
		for len(p) > 0 {
			n, e := w.Write(p)
			if e != nil {
				return e
			}
			if n == 0 {
				return io.ErrShortWrite
			}
			p = p[n:]
		}
	}
	return nil
}

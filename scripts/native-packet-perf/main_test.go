package main

import (
	"encoding/binary"
	"testing"

	"github.com/sanderstripa/connect-core/internal/ipvpn"
)

func TestReflectorProducesValidIPv4UDPReply(t *testing.T) {
	p := make([]byte, 32)
	p[0] = 0x45
	p[8] = 64
	p[9] = 17
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	copy(p[12:16], []byte{10, 231, 0, 2})
	copy(p[16:20], []byte{10, 232, 0, 1})
	binary.BigEndian.PutUint16(p[20:22], 41000)
	binary.BigEndian.PutUint16(p[22:24], 19082)
	binary.BigEndian.PutUint16(p[24:26], 12)
	copy(p[28:], "echo")
	d := &reflector{packets: make(chan []byte, 1), done: make(chan struct{})}
	if _, err := d.Write(p); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 100)
	n, err := d.Read(response)
	if err != nil {
		t.Fatal(err)
	}
	src, dst, err := ipvpn.Packet(response[:n])
	if err != nil || src.String() != "10.232.0.1" || dst.String() != "10.231.0.2" {
		t.Fatal("invalid reply", src, dst, err)
	}
	if binary.BigEndian.Uint16(response[20:22]) != 19082 || binary.BigEndian.Uint16(response[22:24]) != 41000 || string(response[28:n]) != "echo" {
		t.Fatal("reply changed payload or ports")
	}
}

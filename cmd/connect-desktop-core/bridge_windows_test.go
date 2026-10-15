//go:build windows

package main

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/sanderstripa/connect-core/internal/desktop"
	"github.com/sanderstripa/connect-core/internal/ipvpn"
)

func TestNativeBridgeInvalidPacketDoesNotEndSession(t *testing.T) {
	reader, writer := net.Pipe()
	defer reader.Close()
	defer writer.Close()
	b := &nativeBridge{conn: reader, done: make(chan struct{}), ack: make(chan uint32, 1), stats: &ipvpn.Stats{}}
	v := b.view()
	go b.read()
	// The bridge forwards the bounded envelope to the existing IP-policy layer.
	// Invalid payload lengths must not close the channel before the next packet.
	valid := make([]byte, 28)
	valid[0] = 0x45
	valid[8] = 64
	valid[9] = 17
	binary.BigEndian.PutUint16(valid[2:4], uint16(len(valid)))
	copy(valid[12:16], []byte{10, 231, 0, 2})
	copy(valid[16:20], []byte{10, 232, 0, 1})
	binary.BigEndian.PutUint16(valid[20:22], 53000)
	binary.BigEndian.PutUint16(valid[22:24], 53)
	binary.BigEndian.PutUint16(valid[24:26], 8)
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(valid[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(valid[10:12], ^uint16(sum))
	if _, _, err := ipvpn.Packet(valid); err != nil {
		t.Fatal(err)
	}
	written := make(chan error, 1)
	go func() {
		for _, p := range [][]byte{nil, make([]byte, ipvpn.MTU+1), valid} {
			if err := desktop.Write(writer, desktop.FromTUN, p); err != nil {
				written <- err
				return
			}
		}
		written <- nil
	}()
	select {
	case <-v.packets.Ready():
		p, ok := v.packets.Pop()
		if !ok || !bytes.Equal(p.Data, valid) {
			t.Fatal("next bounded packet lost")
		}
	case <-b.done:
		t.Fatal("malformed packet ended helper channel")
	case <-time.After(time.Second):
		t.Fatal("bridge stopped forwarding")
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	if b.stats.InvalidTunDrops.Load() != 2 || b.stats.Dropped.Load() != 2 {
		t.Fatal("invalid packet drops not accounted")
	}
	select {
	case <-b.done:
		t.Fatal("channel unexpectedly closed")
	default:
	}
	writer.Close()
	select {
	case <-b.done:
	case <-time.After(time.Second):
		t.Fatal("closed pipe did not unblock bridge")
	}
}

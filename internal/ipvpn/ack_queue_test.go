package ipvpn

import (
	"encoding/binary"
	"testing"
	"time"
)

func ackPacket(flags byte, payload int) []byte {
	p := make([]byte, 40+payload)
	p[0] = 0x45
	p[8] = 64
	p[9] = 6
	p[32] = 0x50
	p[33] = flags
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	copy(p[12:16], []byte{10, 231, 0, 2})
	copy(p[16:20], []byte{8, 8, 8, 8})
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(p[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(p[10:12], ^uint16(sum))
	return p
}
func TestACKClassifierDoesNotPrioritizeDataOrStreamBoundaries(t *testing.T) {
	for _, c := range []struct {
		flags   byte
		payload int
		want    bool
	}{{0x10, 0, true}, {0xd0, 0, true}, {0x18, 0, false}, {0x12, 0, false}, {0x11, 0, false}, {0x14, 0, false}, {0x10, 1, false}, {0, 0, false}} {
		if got := PureTCPACK(ackPacket(c.flags, c.payload)); got != c.want {
			t.Fatalf("flags=%x payload=%d classified %v", c.flags, c.payload, got)
		}
	}
	p := ackPacket(0x10, 0)
	p[10] ^= 1
	if PureTCPACK(p) {
		t.Fatal("bad IPv4 checksum prioritized")
	}
}
func TestACKBypassesBulkWithoutStarvingData(t *testing.T) {
	q := NewAckQueue(4096)
	for i := 0; i < 4096; i++ {
		p := ackPacket(0x18, 1000)
		binary.BigEndian.PutUint16(p[20:22], uint16(i))
		if !q.Push(QueuedPacket{Data: p}) {
			t.Fatal("bulk lost capacity")
		}
	}
	ack := ackPacket(0x10, 0)
	for i := 0; i < 16; i++ {
		p := append([]byte(nil), ack...)
		binary.BigEndian.PutUint16(p[20:22], uint16(i))
		if !q.Push(QueuedPacket{Data: p}) {
			t.Fatal("feedback dropped behind full bulk")
		}
	}
	for i := 0; i < 8; i++ {
		p, ok := q.Pop()
		if !ok || !PureTCPACK(p.Data) || binary.BigEndian.Uint16(p.Data[20:22]) != uint16(i) {
			t.Fatal("feedback FIFO blocked by bulk")
		}
	}
	p, _ := q.Pop()
	if PureTCPACK(p.Data) || binary.BigEndian.Uint16(p.Data[20:22]) != 0 {
		t.Fatal("bulk starved")
	}
	for i := 8; i < 16; i++ {
		p, _ := q.Pop()
		if !PureTCPACK(p.Data) || binary.BigEndian.Uint16(p.Data[20:22]) != uint16(i) {
			t.Fatal("feedback ordering changed")
		}
	}
	for i := 1; i < 4096; i++ {
		p, ok := q.Pop()
		if !ok || binary.BigEndian.Uint16(p.Data[20:22]) != uint16(i) {
			t.Fatal("bulk FIFO changed", i)
		}
	}
	if _, ok := q.Pop(); ok {
		t.Fatal("stale packet replay")
	}
}
func TestACKQueueBoundedAndWakesAfterDrain(t *testing.T) {
	q := NewAckQueue(2)
	ack := ackPacket(0x10, 0)
	for i := 0; i < 130; i++ {
		if !q.Push(QueuedPacket{Data: ack}) {
			t.Fatal("capacity", i)
		}
	}
	if q.Push(QueuedPacket{Data: ack}) {
		t.Fatal("queue unbounded")
	}
	for i := 0; i < 130; i++ {
		if _, ok := q.Pop(); !ok {
			t.Fatal("missing packet")
		}
	}
	select {
	case <-q.Ready():
	default:
	}
	if !q.Push(QueuedPacket{Data: ack}) {
		t.Fatal("queue did not reuse capacity")
	}
	select {
	case <-q.Ready():
	case <-time.After(time.Second):
		t.Fatal("lost wakeup")
	}
}

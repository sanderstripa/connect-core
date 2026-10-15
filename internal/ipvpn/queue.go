package ipvpn

import (
	"sync/atomic"
	"time"
)

// PacketQueue retains bounded FIFO ordering. Experimental flow scheduling was
// rejected after same-host comparisons showed a throughput regression.
type PacketQueue struct {
	packets chan QueuedPacket
	samples atomic.Uint64
}

func NewPacketQueue(capacity int) *PacketQueue {
	if capacity < 2 {
		panic("packet queue capacity too small")
	}
	return &PacketQueue{packets: make(chan QueuedPacket, capacity)}
}
func (q *PacketQueue) Ready() <-chan QueuedPacket { return q.packets }
func (q *PacketQueue) Push(packet QueuedPacket) bool {
	packet.At = time.Time{}
	if q.samples.Add(1)%timingSampleEvery == 0 {
		packet.At = time.Now()
	}
	select {
	case q.packets <- packet:
		return true
	default:
		return false
	}
}
func (q *PacketQueue) Pop() (QueuedPacket, bool) {
	select {
	case packet := <-q.packets:
		return packet, true
	default:
		return QueuedPacket{}, false
	}
}

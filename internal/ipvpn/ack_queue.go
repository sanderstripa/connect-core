package ipvpn

import "sync/atomic"

// AckQueue separates small TCP feedback from queued bulk data. It preserves
// FIFO in each class and serves bulk after at most eight priority packets.
// Only egress queues use it; authorization and receive ordering are unchanged.
type AckQueue struct {
	bulk, acks  *PacketQueue
	ready       chan struct{}
	burst       int // single consumer, like PacketQueue.Pop
	Prioritized atomic.Uint64
}

func NewAckQueue(capacity int) *AckQueue {
	return &AckQueue{bulk: NewPacketQueue(capacity), acks: NewPacketQueue(128), ready: make(chan struct{}, 1)}
}
func PureTCPACK(p []byte) bool {
	// Data, FIN/RST/SYN and fragments must never jump earlier stream data.
	if len(p) < 40 || len(p) > 80 || p[9] != 6 || p[33]&0x3f != 0x10 || 20+int(p[32]>>4)*4 != len(p) {
		return false
	}
	_, _, err := Packet(p)
	return err == nil
}
func (q *AckQueue) Push(p QueuedPacket) bool {
	ok := false
	if PureTCPACK(p.Data) {
		ok = q.acks.Push(p)
		if ok {
			q.Prioritized.Add(1)
		}
	}
	if !ok {
		ok = q.bulk.Push(p)
	}
	if ok {
		select {
		case q.ready <- struct{}{}:
		default:
		}
	}
	return ok
}
func (q *AckQueue) Ready() <-chan struct{} { return q.ready }
func (q *AckQueue) Pop() (QueuedPacket, bool) {
	if q.burst < 8 {
		if p, ok := q.acks.Pop(); ok {
			q.burst++
			return p, true
		}
	}
	if p, ok := q.bulk.Pop(); ok {
		q.burst = 0
		return p, true
	}
	if p, ok := q.acks.Pop(); ok {
		q.burst = 1
		return p, true
	}
	return QueuedPacket{}, false
}

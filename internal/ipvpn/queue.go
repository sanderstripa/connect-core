package ipvpn

import (
	"sync"
	"time"
)

type flowKey [13]byte
type queueSlot struct {
	packet QueuedPacket
	next   int
}
type flowQueue struct{ head, tail int }

// PacketQueue preserves ordering within each IP flow and serves active flows in
// round-robin order. A bounded reserve admits new short flows while an existing
// bulk flow fills its queue. Authorization still happens outside this scheduler.
// Slots and scheduling storage are fixed; no per-flow payload rings accumulate.
type PacketQueue struct {
	mu                                      sync.Mutex
	ready                                   chan struct{}
	slots                                   []queueSlot
	flows                                   map[flowKey]*flowQueue
	active                                  []flowKey
	head, activeCount, count, free, reserve int
	samples                                 uint64
}

func NewPacketQueue(capacity int) *PacketQueue {
	if capacity < 2 {
		panic("packet queue capacity too small")
	}
	q := &PacketQueue{ready: make(chan struct{}, 1), slots: make([]queueSlot, capacity), flows: make(map[flowKey]*flowQueue), active: make([]flowKey, capacity), reserve: capacity / 64}
	if q.reserve < 1 {
		q.reserve = 1
	}
	for i := range q.slots {
		q.slots[i].next = i + 1
	}
	q.slots[capacity-1].next = -1
	return q
}

func packetFlow(p []byte) (key flowKey) {
	// Native input has not been validated yet. Parsing here is bounded only;
	// the existing certificate/source/destination checks remain mandatory.
	if len(p) < 20 {
		return key
	}
	copy(key[:8], p[12:20])
	key[8] = p[9]
	if (p[9] == 6 || p[9] == 17) && len(p) >= 24 {
		copy(key[9:], p[20:24])
	}
	if p[9] == 1 && len(p) >= 28 {
		copy(key[9:11], p[24:26])
	}
	return key
}

func (q *PacketQueue) Ready() <-chan struct{} { return q.ready }

func (q *PacketQueue) Push(packet QueuedPacket) bool {
	key := packetFlow(packet.Data)
	q.mu.Lock()
	defer q.mu.Unlock()
	flow := q.flows[key]
	if q.count == len(q.slots) || (flow != nil && q.count >= len(q.slots)-q.reserve) {
		return false
	}
	index := q.free
	q.samples++
	packet.At = time.Time{}
	if q.samples%timingSampleEvery == 0 {
		packet.At = time.Now()
	}
	q.free = q.slots[index].next
	q.slots[index] = queueSlot{packet: packet, next: -1}
	if flow == nil {
		flow = &flowQueue{head: index, tail: index}
		q.flows[key] = flow
		q.active[(q.head+q.activeCount)%len(q.active)] = key
		q.activeCount++
	} else {
		q.slots[flow.tail].next = index
		flow.tail = index
	}
	q.count++
	select {
	case q.ready <- struct{}{}:
	default:
	}
	return true
}

func (q *PacketQueue) Pop() (QueuedPacket, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.count == 0 {
		return QueuedPacket{}, false
	}
	key := q.active[q.head]
	q.head = (q.head + 1) % len(q.active)
	q.activeCount--
	flow := q.flows[key]
	index := flow.head
	packet := q.slots[index].packet
	flow.head = q.slots[index].next
	if flow.head < 0 {
		delete(q.flows, key)
	} else {
		q.active[(q.head+q.activeCount)%len(q.active)] = key
		q.activeCount++
	}
	q.slots[index] = queueSlot{next: q.free}
	q.free = index
	q.count--
	if q.count > 0 {
		select {
		case q.ready <- struct{}{}:
		default:
		}
	}
	return packet, true
}

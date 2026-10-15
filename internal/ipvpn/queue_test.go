package ipvpn

import (
	"encoding/binary"
	"testing"
)

func flowPacket(port uint16, sequence byte) QueuedPacket {
	p := udp("10.231.0.2", "10.232.0.1", []byte{sequence})
	binary.BigEndian.PutUint16(p[20:22], port)
	return QueuedPacket{Data: p}
}

func TestPacketQueueAdmitsShortFlowDuringBulkLoad(t *testing.T) {
	q := NewPacketQueue(64)
	for i := 0; i < 63; i++ {
		if !q.Push(flowPacket(1, byte(i))) {
			t.Fatal("bulk capacity lost")
		}
	}
	if q.Push(flowPacket(1, 99)) {
		t.Fatal("bulk consumed short-flow reserve")
	}
	if !q.Push(flowPacket(2, 200)) {
		t.Fatal("short flow denied by bulk")
	}
	if q.Push(flowPacket(3, 201)) {
		t.Fatal("queue capacity exceeded")
	}
	first, _ := q.Pop()
	second, _ := q.Pop()
	if first.Data[28] != 0 || second.Data[28] != 200 {
		t.Fatal("short flow stuck behind bulk")
	}
	for i := 1; i < 63; i++ {
		p, ok := q.Pop()
		if !ok || p.Data[28] != byte(i) {
			t.Fatal("bulk FIFO order changed", i)
		}
	}
	if _, ok := q.Pop(); ok {
		t.Fatal("queue not empty")
	}
	// Slots and active-ring entries are reusable after draining, with no stale flow.
	for round := 0; round < 100; round++ {
		if !q.Push(flowPacket(3, byte(round))) {
			t.Fatal("slot leaked")
		}
		p, ok := q.Pop()
		if !ok || p.Data[28] != byte(round) {
			t.Fatal("stale packet replayed")
		}
	}
}

func TestPacketQueueRoundRobinPreservesEachFlow(t *testing.T) {
	q := NewPacketQueue(64)
	for flow := uint16(1); flow <= 4; flow++ {
		for seq := byte(0); seq < 8; seq++ {
			if !q.Push(flowPacket(flow, seq)) {
				t.Fatal("unexpected full")
			}
		}
	}
	for seq := byte(0); seq < 8; seq++ {
		for flow := uint16(1); flow <= 4; flow++ {
			p, ok := q.Pop()
			if !ok || binary.BigEndian.Uint16(p.Data[20:22]) != flow || p.Data[28] != seq {
				t.Fatal("unfair or reordered packet")
			}
		}
	}
}

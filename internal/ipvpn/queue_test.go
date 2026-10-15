package ipvpn

import "testing"

func TestPacketQueueBoundedFIFOAndReuse(t *testing.T) {
	q := NewPacketQueue(64)
	for round := 0; round < 100; round++ {
		for i := 0; i < 64; i++ {
			if !q.Push(QueuedPacket{Data: []byte{byte(i)}}) {
				t.Fatal("capacity lost", round, i)
			}
		}
		if q.Push(QueuedPacket{}) {
			t.Fatal("unbounded queue")
		}
		for i := 0; i < 64; i++ {
			var p QueuedPacket
			select {
			case p = <-q.Ready():
			default:
				t.Fatal("queued packet not signalled")
			}
			if len(p.Data) != 1 || p.Data[0] != byte(i) {
				t.Fatal("FIFO order changed", round, i)
			}
		}
		if _, ok := q.Pop(); ok {
			t.Fatal("stale packet replayed")
		}
	}
}

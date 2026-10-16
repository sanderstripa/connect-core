package ipvpn

import (
	"fmt"
	"io"
	"sync/atomic"
	"time"
)

// Timing measures local waiting only. It never records addresses or payloads.
type Timing struct {
	count, nanos, maximum, over1ms, over10ms, over50ms atomic.Uint64
	attempts                                           atomic.Uint64
}

// Sample timing to keep diagnostics from dominating the packet hot path.
// Drop counters remain exact and are never sampled.
const timingSampleEvery = 64

func (t *Timing) Begin() time.Time {
	if t.attempts.Add(1)%timingSampleEvery != 0 {
		return time.Time{}
	}
	return time.Now()
}
func (t *Timing) End(start time.Time) {
	if !start.IsZero() {
		t.Observe(time.Since(start))
	}
}

func (t *Timing) Observe(d time.Duration) {
	if d < 0 {
		d = 0
	}
	n := uint64(d)
	t.count.Add(1)
	t.nanos.Add(n)
	for old := t.maximum.Load(); n > old; old = t.maximum.Load() {
		if t.maximum.CompareAndSwap(old, n) {
			break
		}
	}
	if d >= time.Millisecond {
		t.over1ms.Add(1)
	}
	if d >= 10*time.Millisecond {
		t.over10ms.Add(1)
	}
	if d >= 50*time.Millisecond {
		t.over50ms.Add(1)
	}
}

func (t *Timing) Report(w io.Writer, name string) {
	count := t.count.Load()
	var average uint64
	if count > 0 {
		average = t.nanos.Load() / count
	}
	fmt.Fprintf(w, "CONNECT stage: name=%s sample_every=%d samples=%d average_us=%d max_us=%d over_1ms=%d over_10ms=%d over_50ms=%d\n", name, timingSampleEvery, count, average/1000, t.maximum.Load()/1000, t.over1ms.Load(), t.over10ms.Load(), t.over50ms.Load())
}

// QueuedPacket timestamps application queues without changing wire/IPC framing.
type QueuedPacket struct {
	Data []byte
	At   time.Time
}

func (s *Stats) Report(w io.Writer) {
	policy, queue, inactive, ring := s.PolicyDrops.Load(), s.QueueDrops.Load(), s.InactiveDrops.Load(), s.RingDrops.Load()
	invalid := s.InvalidTunDrops.Load()
	var other uint64
	if total := s.Dropped.Load(); total > policy+queue+inactive+ring+invalid {
		other = total - policy - queue - inactive - ring - invalid
	}
	fmt.Fprintf(w, "CONNECT drop reasons: policy=%d queue_capacity=%d inactive=%d wintun=%d invalid_tun=%d other=%d\n", policy, queue, inactive, ring, invalid, other)
	s.NativeQueue.Report(w, "native_queue")
	s.AckQueue.Report(w, "tcp_ack_queue")
	s.ReceiveQueue.Report(w, "receive_queue")
	s.SendQueue.Report(w, "server_send_queue")
	s.DatagramSend.Report(w, "quic_send")
	s.DeviceWrite.Report(w, "tun_write")
}

func (s *Stats) reportPeriodically(ctxDone <-chan struct{}, w io.Writer) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctxDone:
			return
		case <-ticker.C:
			s.Report(w)
		}
	}
}

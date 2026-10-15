package ipvpn

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"sync"
	"time"
)

// packetHub keeps the native interface alive across authenticated sessions.
// Disconnected packets are dropped; no queued application bytes are replayed.
type packetHub struct {
	d     Device
	mu    sync.Mutex
	view  *packetView
	done  chan struct{}
	err   error
	stats *Stats
}
type packetView struct {
	hub     *packetHub
	packets *PacketQueue
	done    chan struct{}
	once    sync.Once
}

func newHub(d Device, stats *Stats) *packetHub {
	h := &packetHub{d: d, done: make(chan struct{}), stats: stats}
	go func() {
		defer close(h.done)
		b := make([]byte, 65535)
		for {
			n, e := d.Read(b)
			if e != nil {
				h.mu.Lock()
				h.err = e
				h.mu.Unlock()
				return
			}
			h.mu.Lock()
			v := h.view
			if v == nil {
				stats.InactiveDrops.Add(1)
				stats.Dropped.Add(1)
			} else {
				if !v.packets.Push(QueuedPacket{Data: append([]byte{}, b[:n]...)}) {
					stats.QueueDrops.Add(1)
					stats.Dropped.Add(1)
				}
			}
			h.mu.Unlock()
		}
	}()
	return h
}
func (h *packetHub) session() *packetView {
	v := &packetView{h, NewPacketQueue(PacketQueueSize), make(chan struct{}), sync.Once{}}
	h.mu.Lock()
	h.view = v
	h.mu.Unlock()
	return v
}
func (h *packetHub) close() { _ = h.d.Close(); <-h.done }
func (v *packetView) Read(b []byte) (int, error) {
	for {
		select {
		case <-v.done:
			return 0, io.EOF
		case <-v.hub.done:
			v.hub.mu.Lock()
			e := v.hub.err
			v.hub.mu.Unlock()
			return 0, e
		case p := <-v.packets.Ready():
			v.hub.stats.NativeQueue.End(p.At)
			return copy(b, p.Data), nil
		}
	}
}
func (v *packetView) Write(b []byte) (int, error) {
	select {
	case <-v.done:
		return 0, io.EOF
	default:
		return v.hub.d.Write(b)
	}
}
func (v *packetView) Close() error {
	v.once.Do(func() {
		v.hub.mu.Lock()
		if v.hub.view == v {
			v.hub.view = nil
		}
		close(v.done)
		v.hub.mu.Unlock()
	})
	return nil
}

type Event struct {
	Version   int               `json:"ipc_version"`
	State     string            `json:"state"`
	Interface string            `json:"interface"`
	Stats     map[string]uint64 `json:"stats,omitempty"`
}

// Managed uses the existing IP v2 wire format. Only fresh authenticated sessions
// are retried. The interface is retained and drained during disconnection.
func Managed(ctx context.Context, cfg Config, t *tls.Config, open func(string) (Device, error), stats *Stats, event func(Event)) error {
	policies, e := cfg.Validate(false)
	if e != nil {
		return e
	}
	emit := func(state string) {
		if event != nil {
			event(Event{Version: 1, State: state, Interface: cfg.Interface, Stats: stats.Snapshot()})
		}
	}
	emit("authenticating")
	c, e := Dial(ctx, cfg.Endpoint, t, policies[""].Device)
	if e != nil {
		if ctx.Err() != nil {
			emit("stopped")
			return nil
		}
		emit("failed")
		return e
	}
	d, e := open(cfg.Interface)
	if e != nil {
		_ = c.CloseWithError(0, "interface failed")
		emit("failed")
		return e
	}
	h := newHub(d, stats)
	defer h.close()
	stop := context.AfterFunc(ctx, func() { _ = d.Close() })
	defer stop()
	for {
		view := h.session()
		emit("ready")
		e = Client(ctx, c, view, policies[""], stats)
		if ctx.Err() != nil {
			emit("stopped")
			return nil
		}
		select {
		case <-h.done:
			h.mu.Lock()
			e = h.err
			h.mu.Unlock()
			emit("failed")
			return e
		default:
		}
		emit("reconnecting")
		delay := 100 * time.Millisecond
		for {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				emit("stopped")
				return nil
			case <-h.done:
				timer.Stop()
				emit("failed")
				return errors.New("native interface stopped")
			case <-timer.C:
			}
			c, e = Dial(ctx, cfg.Endpoint, t, policies[""].Device)
			if e == nil {
				break
			}
			// Backoff is bounded; credentials and allowlists are never relaxed.
			if delay < 2*time.Second {
				delay *= 2
				if delay > 2*time.Second {
					delay = 2 * time.Second
				}
			}
		}
	}
}

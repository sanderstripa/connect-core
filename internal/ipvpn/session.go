package ipvpn

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/sanderstripa/connect-core/internal/core"
)

// Device is a packet interface. Close MUST unblock Read and Write.
type Device interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
}

// PacketQueueSize bounds per-session bursts; server payload memory has a separate global cap.
const PacketQueueSize = 256
const maxQueuedPayload = 64 << 20

type Stats struct {
	Sent, Received, Dropped, SentBytes, ReceivedBytes               atomic.Uint64
	PolicyDrops, QueueDrops, InactiveDrops, RingDrops               atomic.Uint64
	NativeQueue, ReceiveQueue, SendQueue, DatagramSend, DeviceWrite Timing
}

func (s *Stats) Snapshot() map[string]uint64 {
	return map[string]uint64{"sent_packets": s.Sent.Load(), "received_packets": s.Received.Load(), "dropped_packets": s.Dropped.Load()}
}
func TLS(c Config, server bool) (*tls.Config, error) {
	trust := c.Trust
	if server {
		trust.AllowedClients = nil
		for pin := range c.Clients {
			trust.AllowedClients = append(trust.AllowedClients, pin)
		}
	}
	t, e := core.TLS(trust, server)
	if e != nil {
		return nil, e
	}
	t.NextProtos = []string{ALPN}
	return t, nil
}
func QUIC() *quic.Config {
	return &quic.Config{
		Versions:        []quic.Version{quic.Version1},
		EnableDatagrams: true, Allow0RTT: false, HandshakeIdleTimeout: 3 * time.Second, MaxIdleTimeout: 15 * time.Second, KeepAlivePeriod: 5 * time.Second,
		MaxIncomingStreams: 1, MaxIncomingUniStreams: -1,
		InitialStreamReceiveWindow: 4096, MaxStreamReceiveWindow: 4096, InitialConnectionReceiveWindow: 4096, MaxConnectionReceiveWindow: 4096,
		InitialPacketSize: 1200, DisablePathMTUDiscovery: true,
	}
}
func negotiated(c *quic.Conn) bool {
	return c.ConnectionState().TLS.NegotiatedProtocol == ALPN && c.ConnectionState().SupportsDatagrams.Remote
}

func Dial(ctx context.Context, address string, t *tls.Config, want netip.Addr) (*quic.Conn, error) {
	hctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	c, e := quic.DialAddr(hctx, address, t, QUIC())
	if e != nil {
		return nil, e
	}
	fail := func(e error) (*quic.Conn, error) { _ = c.CloseWithError(1, "session rejected"); return nil, e }
	if !negotiated(c) {
		return fail(errors.New("ALPN/datagrams required"))
	}
	s, e := c.OpenStreamSync(hctx)
	if e != nil {
		return fail(e)
	}
	_ = s.SetDeadline(time.Now().Add(5 * time.Second))
	if e = hello(s, netip.Addr{}); e != nil {
		return fail(e)
	}
	ip, e := readHello(s, false)
	if e != nil {
		return fail(e)
	}
	if ip != want {
		return fail(errors.New("server assigned unexpected device IP"))
	}
	_ = s.SetDeadline(time.Time{})
	go monitor(c, s)
	return c, nil
}

// The control stream remains open for the lifetime of the session. Any further
// bytes or EOF close the session; future commands require a new wire revision.
func monitor(c *quic.Conn, s *quic.Stream) {
	var b [1]byte
	_, _ = s.Read(b[:])
	_ = c.CloseWithError(1, "control stream closed")
}

func Client(ctx context.Context, c *quic.Conn, d Device, p Policy, stats *Stats) error {
	defer func() {
		stats.Report(os.Stderr)
		s := c.ConnectionStats()
		fmt.Fprintf(os.Stderr, "CONNECT transport stats: rtt_ms=%d sent_packets=%d received_packets=%d lost_packets=%d device_dropped=%d\n", s.SmoothedRTT.Milliseconds(), s.PacketsSent, s.PacketsReceived, s.PacketsLost, stats.Dropped.Load())
	}()
	parent := ctx
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go stats.reportPeriodically(ctx.Done(), os.Stderr)
	defer c.CloseWithError(0, "client stopped")
	stop := context.AfterFunc(ctx, func() { _ = c.CloseWithError(0, "cancelled"); _ = d.Close() })
	defer stop()
	stopConn := context.AfterFunc(c.Context(), func() { _ = d.Close() })
	defer stopConn()
	defer d.Close()
	result := make(chan error, 3)
	incoming := make(chan QueuedPacket, PacketQueueSize)
	go func() {
		buf := make([]byte, 65535)
		for {
			n, e := d.Read(buf)
			if e != nil {
				result <- e
				return
			}
			pkt := buf[:n]
			if !p.Allows(pkt, true) {
				stats.PolicyDrops.Add(1)
				stats.Dropped.Add(1)
				continue
			}
			start := time.Now()
			e = c.SendDatagram(pkt)
			stats.DatagramSend.Observe(time.Since(start))
			if e != nil {
				result <- e
				return
			}
			stats.Sent.Add(1)
			stats.SentBytes.Add(uint64(len(pkt)))
		}
	}()
	go func() { result <- receiveToQueue(ctx, c, p, stats, incoming, nil, false) }()
	go func() {
		for {
			select {
			case <-ctx.Done():
				result <- ctx.Err()
				return
			case <-c.Context().Done():
				result <- context.Cause(c.Context())
				return
			case queued := <-incoming:
				stats.ReceiveQueue.Observe(time.Since(queued.At))
				pkt := queued.Data
				start := time.Now()
				n, e := d.Write(pkt)
				stats.DeviceWrite.Observe(time.Since(start))
				if e != nil {
					result <- e
					return
				}
				if n != len(pkt) {
					result <- io.ErrShortWrite
					return
				}
				stats.Received.Add(1)
				stats.ReceivedBytes.Add(uint64(len(pkt)))
			}
		}
	}()
	e := <-result
	if cause := context.Cause(c.Context()); cause != nil {
		e = cause
	}
	_ = c.CloseWithError(0, "packet pump stopped")
	_ = d.Close()
	cancel()
	<-result
	<-result
	if parent.Err() != nil {
		return nil
	}
	return e
}

type peer struct {
	conn     *quic.Conn
	policy   Policy
	queue    chan QueuedPacket
	incoming chan QueuedPacket
}

// Drain QUIC's bounded DATAGRAM receive queue independently of a potentially
// slow OS TUN write. Returned DATAGRAM slices are owned by this caller.
func receiveToQueue(ctx context.Context, c *quic.Conn, p Policy, stats *Stats, out chan QueuedPacket, budget *atomic.Int64, incoming bool) error {
	for {
		packet, err := c.ReceiveDatagram(ctx)
		if err != nil {
			return err
		}
		if !p.Allows(packet, incoming) {
			stats.PolicyDrops.Add(1)
			stats.Dropped.Add(1)
			continue
		}
		size := int64(len(packet))
		if budget != nil && budget.Add(size) > maxQueuedPayload {
			budget.Add(-size)
			stats.QueueDrops.Add(1)
			stats.Dropped.Add(1)
			continue
		}
		select {
		case out <- QueuedPacket{Data: packet, At: time.Now()}:
		default:
			if budget != nil {
				budget.Add(-size)
			}
			stats.QueueDrops.Add(1)
			stats.Dropped.Add(1)
		}
	}
}

// Serve owns d and closes it on return. The shared TUN reader routes replies to
// the certificate-bound address, with a bounded nonblocking queue per peer.
func Serve(ctx context.Context, l *quic.Listener, d Device, policies map[string]Policy, stats *Stats) error {
	return ServeControlled(ctx, l, d, NewControl(policies), stats)
}

func ServeControlled(ctx context.Context, l *quic.Listener, d Device, control *Control, stats *Stats) error {
	parent := ctx
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go stats.reportPeriodically(ctx.Done(), os.Stderr)
	defer stats.Report(os.Stderr)
	var mu sync.Mutex
	var writeMu sync.Mutex
	var queuedPayload atomic.Int64
	var wg sync.WaitGroup
	peers := map[netip.Addr]*peer{}
	pending := make(chan struct{}, 32)
	stop := context.AfterFunc(ctx, func() { _ = l.Close(); _ = d.Close() })
	defer stop()
	defer func() {
		cancel()
		_ = l.Close()
		_ = d.Close()
		mu.Lock()
		for _, p := range peers {
			_ = p.conn.CloseWithError(0, "server stopped")
		}
		mu.Unlock()
		wg.Wait()
	}()
	readErr := make(chan error, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 65535)
		for {
			n, e := d.Read(buf)
			if e != nil {
				readErr <- e
				cancel()
				return
			}
			pkt := buf[:n]
			_, dst, e := Packet(pkt)
			if e != nil {
				stats.Dropped.Add(1)
				continue
			}
			mu.Lock()
			p := peers[dst]
			if p == nil || !p.policy.Allows(pkt, false) {
				stats.Dropped.Add(1)
			} else {
				size := int64(len(pkt))
				if queuedPayload.Add(size) > maxQueuedPayload {
					queuedPayload.Add(-size)
					stats.QueueDrops.Add(1)
					stats.Dropped.Add(1)
				} else {
					select {
					case p.queue <- QueuedPacket{Data: append([]byte(nil), pkt...), At: time.Now()}:
					default:
						queuedPayload.Add(-size)
						stats.QueueDrops.Add(1)
						stats.Dropped.Add(1)
					}
				}
			}
			mu.Unlock()
		}
	}()
	for {
		c, e := l.Accept(ctx)
		if e != nil {
			if parent.Err() != nil {
				return nil
			}
			select {
			case re := <-readErr:
				return fmt.Errorf("TUN read: %w", re)
			default:
			}
			if ctx.Err() != nil {
				return nil
			}
			return e
		}
		select {
		case pending <- struct{}{}:
		default:
			_ = c.CloseWithError(2, "capacity")
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-pending }()
			defer c.CloseWithError(0, "session ended")
			if !negotiated(c) || len(c.ConnectionState().TLS.PeerCertificates) == 0 {
				return
			}
			pin := core.Fingerprint(c.ConnectionState().TLS.PeerCertificates[0].Raw)
			policy, ok := control.Policy(pin)
			if !ok {
				return
			}
			hctx, hcancel := context.WithTimeout(ctx, 5*time.Second)
			s, e := c.AcceptStream(hctx)
			hcancel()
			if e != nil {
				return
			}
			_ = s.SetDeadline(time.Now().Add(5 * time.Second))
			if _, e = readHello(s, true); e != nil {
				return
			}
			p := &peer{conn: c, policy: policy}
			if !control.Admit(pin, func() { _ = c.CloseWithError(4, "access revoked") }) {
				if control.Busy(pin) {
					_ = c.CloseWithError(3, "device already active")
				} else {
					_ = c.CloseWithError(4, "access denied")
				}
				return
			}
			p.queue = make(chan QueuedPacket, PacketQueueSize)
			p.incoming = make(chan QueuedPacket, PacketQueueSize)
			defer control.Release(pin)
			mu.Lock()
			if peers[policy.Device] != nil {
				mu.Unlock()
				_ = c.CloseWithError(3, "device already active")
				return
			}
			peers[policy.Device] = p
			mu.Unlock()
			defer func() {
				mu.Lock()
				defer mu.Unlock()
				delete(peers, policy.Device)
				for _, queue := range []chan QueuedPacket{p.queue, p.incoming} {
				drain:
					for {
						select {
						case packet := <-queue:
							queuedPayload.Add(-int64(len(packet.Data)))
						default:
							break drain
						}
					}
				}
			}()
			stopPeer := context.AfterFunc(ctx, func() { _ = c.CloseWithError(0, "cancelled") })
			defer stopPeer()
			if e = hello(s, policy.Device); e != nil {
				return
			}
			_ = s.SetDeadline(time.Time{})
			var pumps sync.WaitGroup
			pumps.Add(3)
			go func() { defer pumps.Done(); monitor(c, s) }()
			go func() {
				defer pumps.Done()
				for {
					select {
					case <-c.Context().Done():
						return
					case queued := <-p.queue:
						stats.SendQueue.Observe(time.Since(queued.At))
						pkt := queued.Data
						queuedPayload.Add(-int64(len(pkt)))
						if control.Transfer(pin, false, len(pkt), func() error {
							start := time.Now()
							err := c.SendDatagram(pkt)
							stats.DatagramSend.Observe(time.Since(start))
							return err
						}) != nil {
							_ = c.CloseWithError(1, "send failed")
							return
						}
						stats.Sent.Add(1)
					}
				}
			}()
			go func() {
				defer pumps.Done()
				_ = receiveToQueue(ctx, c, policy, stats, p.incoming, &queuedPayload, true)
				_ = c.CloseWithError(0, "receive stopped")
			}()
			func() {
				for {
					select {
					case <-c.Context().Done():
						return
					case queued := <-p.incoming:
						stats.ReceiveQueue.Observe(time.Since(queued.At))
						pkt := queued.Data
						queuedPayload.Add(-int64(len(pkt)))
						err := control.Transfer(pin, true, len(pkt), func() error {
							writeMu.Lock()
							defer writeMu.Unlock()
							start := time.Now()
							n, err := d.Write(pkt)
							stats.DeviceWrite.Observe(time.Since(start))
							if err == nil && n != len(pkt) {
								return io.ErrShortWrite
							}
							return err
						})
						if err != nil {
							if _, allowed := control.Policy(pin); allowed {
								cancel()
							}
							return
						}
						stats.Received.Add(1)
					}
				}
			}()
			_ = c.CloseWithError(0, "packet pump stopped")
			pumps.Wait()
		}()
	}
}

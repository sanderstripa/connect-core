package ipvpn

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/sanderstripa/connect-core/internal/core"
	"github.com/sanderstripa/connect-core/internal/lab"
)

func udp(src, dst string, payload []byte) []byte {
	p := make([]byte, 28+len(payload))
	p[0] = 0x45
	p[8] = 64
	p[9] = 17
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	binary.BigEndian.PutUint16(p[24:26], uint16(8+len(payload)))
	a, b := netip.MustParseAddr(src).As4(), netip.MustParseAddr(dst).As4()
	copy(p[12:16], a[:])
	copy(p[16:20], b[:])
	copy(p[28:], payload)
	checksum(p)
	return p
}
func checksum(p []byte) {
	p[10] = 0
	p[11] = 0
	var s uint32
	for i := 0; i < 20; i += 2 {
		s += uint32(binary.BigEndian.Uint16(p[i : i+2]))
	}
	for s>>16 != 0 {
		s = (s & 65535) + (s >> 16)
	}
	binary.BigEndian.PutUint16(p[10:12], ^uint16(s))
}
func TestPacketPolicy(t *testing.T) {
	p := Policy{netip.MustParseAddr("10.231.0.2"), []netip.Prefix{netip.MustParsePrefix("10.232.0.1/32")}}
	good := udp("10.231.0.2", "10.232.0.1", []byte{0, 255, 1})
	if !p.Allows(good, true) {
		t.Fatal("valid UDP denied")
	}
	bad := [][]byte{udp("10.231.0.99", "10.232.0.1", nil), udp("10.231.0.2", "10.232.0.9", nil), udp("10.231.0.2", "127.0.0.1", nil), udp("10.231.0.2", "224.0.0.1", nil), good[:19], append(append([]byte{}, good...), 0)}
	for _, off := range []int{0, 2, 6, 8, 9, 10, 24} {
		b := append([]byte(nil), good...)
		b[off] ^= 255
		bad = append(bad, b)
	}
	for i, b := range bad {
		if p.Allows(b, true) {
			t.Fatalf("invalid packet %d accepted", i)
		}
	}
	reply := udp("10.232.0.1", "10.231.0.2", nil)
	if !p.Allows(reply, false) || p.Allows(reply, true) {
		t.Fatal("direction policy")
	}
	for _, flags := range []uint16{0x8000, 0x2000, 1} {
		b := append([]byte{}, good...)
		binary.BigEndian.PutUint16(b[6:8], flags)
		checksum(b)
		if p.Allows(b, true) {
			t.Fatal("fragment accepted")
		}
	}
	max := udp("10.231.0.2", "10.232.0.1", make([]byte, MTU-28))
	if !p.Allows(max, true) {
		t.Fatal("MTU rejected")
	}
	if p.Allows(udp("10.231.0.2", "10.232.0.1", make([]byte, MTU-27)), true) {
		t.Fatal("oversize accepted")
	}
}
func TestHelloVectors(t *testing.T) {
	var b bytes.Buffer
	if hello(&b, netip.Addr{}) != nil {
		t.Fatal("write")
	}
	want := []byte{67, 73, 80, 50, 4, 76, 0, 0, 0, 0, 0, 0}
	if !bytes.Equal(b.Bytes(), want) {
		t.Fatalf("vector %x", b.Bytes())
	}
	if _, e := readHello(bytes.NewReader(want), true); e != nil {
		t.Fatal(e)
	}
	for n := 0; n < 12; n++ {
		if _, e := readHello(bytes.NewReader(want[:n]), true); e == nil {
			t.Fatal("truncated hello")
		}
	}
	for _, i := range []int{0, 4, 6, 7, 8} {
		x := append([]byte{}, want...)
		x[i] ^= 1
		if _, e := readHello(bytes.NewReader(x), true); e == nil {
			t.Fatal("bad hello")
		}
	}
}
func TestConfigFailClosed(t *testing.T) {
	cfg := Config{Version: 2, Environment: "isolated-lab", Endpoint: "192.168.231.1:17444", Interface: "ccip0", DeviceIP: "10.231.0.2", Destinations: []string{"10.232.0.1/32"}}
	if _, e := cfg.Validate(false); e != nil {
		t.Fatal(e)
	}
	for _, ep := range []string{"example.com:443", "0.0.0.0:443", "8.8.8.8:17444", "[::1]:17444", "192.168.231.1:0"} {
		c := cfg
		c.Endpoint = ep
		if _, e := c.Validate(false); e == nil {
			t.Fatal(ep)
		}
	}
	for _, dest := range []string{"0.0.0.0/0", "10.0.0.0/8", "10.231.0.0/24", "192.168.231.0/24", "10.232.0.1/24"} {
		c := cfg
		c.Destinations = []string{dest}
		if _, e := c.Validate(false); e == nil {
			t.Fatal(dest)
		}
	}
	f := filepath.Join(t.TempDir(), "config.json")
	b, _ := json.Marshal(cfg)
	for _, body := range []string{string(b) + " {}", strings.Replace(string(b), "isolated-lab", "production", 1), `{"config_version":2,"unknown":true}`, strings.Repeat(" ", 65537)} {
		if e := os.WriteFile(f, []byte(body), 0600); e != nil {
			t.Fatal(e)
		}
		c, e := Load(f)
		if e == nil {
			_, e = c.Validate(false)
		}
		if e == nil {
			t.Fatal("invalid config accepted")
		}
	}
}

type memoryDevice struct {
	read, write chan []byte
	done        chan struct{}
	once        sync.Once
}

func newDevice() *memoryDevice {
	return &memoryDevice{read: make(chan []byte, 64), write: make(chan []byte, 64), done: make(chan struct{})}
}
func (d *memoryDevice) Read(b []byte) (int, error) {
	select {
	case <-d.done:
		return 0, io.EOF
	case p := <-d.read:
		return copy(b, p), nil
	}
}
func (d *memoryDevice) Write(b []byte) (int, error) {
	select {
	case <-d.done:
		return 0, io.EOF
	case d.write <- append([]byte{}, b...):
		return len(b), nil
	}
}
func (d *memoryDevice) Close() error { d.once.Do(func() { close(d.done) }); return nil }

type fixture struct {
	address     string
	tls         *tls.Config
	server      Config
	device      *memoryDevice
	stats       *Stats
	cancel      context.CancelFunc
	done        chan error
	closeSocket func() error
}

func setup(t testing.TB, configure ...func(*Config)) fixture {
	t.Helper()
	s, c, e := lab.Generate(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	cfg := Config{Version: 2, Environment: "isolated-lab", Endpoint: "127.0.0.1:17444", Interface: "ccip0", Clients: map[string]string{s.AllowedClients[0]: "10.231.0.2"}, Destinations: []string{"10.232.0.1/32"}, Trust: s}
	for _, change := range configure {
		change(&cfg)
	}
	policies, e := cfg.Validate(true)
	if e != nil {
		t.Fatal(e)
	}
	st, e := TLS(cfg, true)
	if e != nil {
		t.Fatal(e)
	}
	ct, e := TLS(Config{Trust: c}, false)
	if e != nil {
		t.Fatal(e)
	}
	l, closeSocket, e := Listen("127.0.0.1:0", st)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	d := newDevice()
	stats := &Stats{}
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, l, d, policies, stats) }()
	t.Cleanup(func() {
		cancel()
		_ = closeSocket()
		select {
		case e := <-done:
			if e != nil {
				t.Error(e)
			}
		case <-time.After(6 * time.Second):
			t.Error("server shutdown stuck")
		}
	})
	return fixture{l.Addr().String(), ct, cfg, d, stats, cancel, done, closeSocket}
}
func receive(t testing.TB, ch <-chan []byte) []byte {
	t.Helper()
	select {
	case p := <-ch:
		return p
	case <-time.After(3 * time.Second):
		t.Fatal("packet timed out")
		return nil
	}
}
func TestQUICPacketVertical(t *testing.T) {
	f := setup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	c, e := Dial(ctx, f.address, f.tls, netip.MustParseAddr("10.231.0.2"))
	if e != nil {
		t.Fatal(e)
	}
	if c.ConnectionState().Used0RTT {
		t.Fatal("0RTT used")
	}
	d := newDevice()
	done := make(chan error, 1)
	stats := &Stats{}
	go func() {
		done <- Client(ctx, c, d, Policy{netip.MustParseAddr("10.231.0.2"), []netip.Prefix{netip.MustParsePrefix("10.232.0.1/32")}}, stats)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("client stuck")
		}
	})
	payload := bytes.Repeat([]byte{0, 255, 42}, 128)
	p := udp("10.231.0.2", "10.232.0.1", payload)
	d.read <- p
	if !bytes.Equal(receive(t, f.device.write), p) {
		t.Fatal("uplink corruption")
	}
	reply := udp("10.232.0.1", "10.231.0.2", payload)
	f.device.read <- reply
	if !bytes.Equal(receive(t, d.write), reply) {
		t.Fatal("downlink corruption")
	}
	// Send spoofed packets past the client frontend: server must enforce policy.
	if e = c.SendDatagram(udp("10.231.0.99", "10.232.0.1", nil)); e != nil {
		t.Fatal(e)
	}
	if e = c.SendDatagram(udp("10.231.0.2", "10.232.0.9", nil)); e != nil {
		t.Fatal(e)
	}
	deadline := time.Now().Add(2 * time.Second)
	for f.stats.Dropped.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if f.stats.Dropped.Load() < 2 {
		t.Fatal("server did not reject spoof/policy")
	}
	select {
	case <-f.device.write:
		t.Fatal("denied packet reached TUN")
	default:
	}
	// Duplicate binding cannot take over an existing session.
	if other, e := Dial(ctx, f.address, f.tls, netip.MustParseAddr("10.231.0.2")); e == nil {
		other.CloseWithError(0, "test")
		t.Fatal("duplicate accepted")
	}
}
func TestQUICAuthentication(t *testing.T) {
	f := setup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	_, foreign, e := lab.Generate(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	bad, e := TLS(Config{Trust: foreign}, false)
	if e != nil {
		t.Fatal(e)
	}
	wrongName := f.tls.Clone()
	wrongName.ServerName = "invalid.test"
	missing := f.tls.Clone()
	missing.Certificates = nil
	wrongALPN := f.tls.Clone()
	wrongALPN.NextProtos = []string{"connect-lab/1"}
	untrusted := f.tls.Clone()
	untrusted.Certificates = bad.Certificates
	for name, ct := range map[string]*tls.Config{"wrong-ca": bad, "wrong-name": wrongName, "missing-certificate": missing, "wrong-alpn": wrongALPN, "untrusted-client": untrusted} {
		t.Run(name, func(t *testing.T) {
			c, e := Dial(ctx, f.address, ct, netip.MustParseAddr("10.231.0.2"))
			if e == nil {
				c.CloseWithError(0, "test")
				t.Fatal("authentication bypass")
			}
		})
	}
	if c, e := Dial(ctx, f.address, f.tls, netip.MustParseAddr("10.231.0.3")); e == nil {
		c.CloseWithError(0, "test")
		t.Fatal("wrong assignment accepted")
	}
}
func TestQUICShutdownAndReconnect(t *testing.T) {
	f := setup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for i := 0; i < 25; i++ {
		c, e := Dial(ctx, f.address, f.tls, netip.MustParseAddr("10.231.0.2"))
		deadline := time.Now().Add(2 * time.Second)
		for e != nil && time.Now().Before(deadline) {
			var duplicate *quic.ApplicationError
			if !errors.As(e, &duplicate) || duplicate.ErrorCode != 3 {
				break
			}
			time.Sleep(time.Millisecond)
			c, e = Dial(ctx, f.address, f.tls, netip.MustParseAddr("10.231.0.2"))
		}
		if e != nil {
			t.Fatal(i, e)
		}
		d := newDevice()
		done := make(chan error, 1)
		go func() {
			done <- Client(ctx, c, d, Policy{netip.MustParseAddr("10.231.0.2"), []netip.Prefix{netip.MustParsePrefix("10.232.0.1/32")}}, &Stats{})
		}()
		p := udp("10.231.0.2", "10.232.0.1", []byte{byte(i)})
		d.read <- p
		if !bytes.Equal(receive(t, f.device.write), p) {
			t.Fatal("reconnect bytes")
		}
		if i == 24 {
			f.cancel()
		} else {
			c.CloseWithError(0, "reconnect")
		}
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("client did not stop")
		}
	}
}

func TestValidCertificateNotAllowlisted(t *testing.T) {
	f := setup(t, func(c *Config) { c.Clients = map[string]string{strings.Repeat("0", 64): "10.231.0.2"} })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if c, e := Dial(ctx, f.address, f.tls, netip.MustParseAddr("10.231.0.2")); e == nil {
		c.CloseWithError(0, "test")
		t.Fatal("valid CA certificate bypassed pin")
	}
}

func TestMismatchedPrivateKey(t *testing.T) {
	f := setup(t)
	c := f.server
	c.Trust.Key = filepath.Join(filepath.Dir(c.Trust.Key), "client.key")
	if _, e := TLS(c, true); e == nil {
		t.Fatal("mismatched key accepted")
	}
}

func TestMalformedControlOverQUIC(t *testing.T) {
	f := setup(t)
	for _, payload := range [][]byte{[]byte("CIP9\x04\x4c\x00\x00\x00\x00\x00\x00"), []byte("CIP2\x04\x4c\x00\x01\x00\x00\x00\x00"), []byte("CIP2")} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		c, e := quic.DialAddr(ctx, f.address, f.tls, QUIC())
		if e != nil {
			cancel()
			t.Fatal(e)
		}
		s, e := c.OpenStreamSync(ctx)
		if e != nil {
			cancel()
			t.Fatal(e)
		}
		if _, e = s.Write(payload); e != nil {
			cancel()
			t.Fatal(e)
		}
		_ = s.Close()
		select {
		case <-c.Context().Done():
		case <-ctx.Done():
			t.Error("malformed session remained open")
		}
		_ = c.CloseWithError(0, "test")
		cancel()
	}
	select {
	case <-f.device.write:
		t.Fatal("unauthorized TUN write")
	default:
	}
}

func TestTwoDeviceReplyIsolation(t *testing.T) {
	_, second, e := lab.Generate(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	secondPair, e := tls.LoadX509KeyPair(second.Cert, second.Key)
	if e != nil {
		t.Fatal(e)
	}
	var secondTLS *tls.Config
	f := setup(t, func(c *Config) {
		original, e := os.ReadFile(c.Trust.CA)
		if e != nil {
			t.Fatal(e)
		}
		foreign, e := os.ReadFile(second.CA)
		if e != nil {
			t.Fatal(e)
		}
		combined := filepath.Join(t.TempDir(), "combined.pem")
		if e = os.WriteFile(combined, append(original, foreign...), 0600); e != nil {
			t.Fatal(e)
		}
		c.Trust.CA = combined
		second.CA = combined
		c.Clients[core.Fingerprint(secondPair.Certificate[0])] = "10.231.0.3"
		secondTLS, e = TLS(Config{Trust: second}, false)
		if e != nil {
			t.Fatal(e)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	c1, e := Dial(ctx, f.address, f.tls, netip.MustParseAddr("10.231.0.2"))
	if e != nil {
		t.Fatal(e)
	}
	defer c1.CloseWithError(0, "test")
	c2, e := Dial(ctx, f.address, secondTLS, netip.MustParseAddr("10.231.0.3"))
	if e != nil {
		t.Fatal(e)
	}
	defer c2.CloseWithError(0, "test")
	p := udp("10.232.0.1", "10.231.0.3", []byte("second-device-only"))
	f.device.read <- p
	got, e := c2.ReceiveDatagram(ctx)
	if e != nil || !bytes.Equal(got, p) {
		t.Fatal("second-device reply", e)
	}
	probe, stop := context.WithTimeout(ctx, 50*time.Millisecond)
	defer stop()
	if _, e = c1.ReceiveDatagram(probe); e == nil {
		t.Fatal("reply leaked across devices")
	}
	// c1 cannot impersonate the other authenticated device.
	if e = c1.SendDatagram(udp("10.231.0.3", "10.232.0.1", nil)); e != nil {
		t.Fatal(e)
	}
	deadline := time.Now().Add(2 * time.Second)
	for f.stats.Dropped.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if f.stats.Dropped.Load() == 0 {
		t.Fatal("cross-device spoof accepted")
	}
}
func FuzzPacket(f *testing.F) {
	f.Add(udp("10.231.0.2", "10.232.0.1", nil))
	f.Add([]byte{0x60})
	f.Fuzz(func(t *testing.T, p []byte) { _, _, _ = Packet(p) })
}
func FuzzHello(f *testing.F) {
	f.Add([]byte{67, 73, 80, 50, 4, 76, 0, 0, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = readHello(bytes.NewReader(b), true) })
}
func BenchmarkPolicy(b *testing.B) {
	p := udp("10.231.0.2", "10.232.0.1", make([]byte, MTU-28))
	policy := Policy{netip.MustParseAddr("10.231.0.2"), []netip.Prefix{netip.MustParsePrefix("10.232.0.1/32")}}
	b.SetBytes(int64(len(p)))
	for b.Loop() {
		if !policy.Allows(p, true) {
			b.Fatal("policy")
		}
	}
}

// Actual encrypted loopback datagram round trips; excludes handshake/TUN and
// counts one useful 1024-byte payload per echo, not Internet link throughput.
func BenchmarkQUICDatagramEcho(b *testing.B) {
	f := setup(b)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c, e := Dial(ctx, f.address, f.tls, netip.MustParseAddr("10.231.0.2"))
	if e != nil {
		b.Fatal(e)
	}
	defer c.CloseWithError(0, "benchmark")
	payload := bytes.Repeat([]byte{42}, 1024)
	req := udp("10.231.0.2", "10.232.0.1", payload)
	reply := udp("10.232.0.1", "10.231.0.2", payload)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-ctx.Done():
				return
			case <-f.device.write:
				select {
				case f.device.read <- reply:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	defer func() { cancel(); <-done }()
	b.SetBytes(1024)
	for b.Loop() {
		if e = c.SendDatagram(req); e != nil {
			b.Fatal(e)
		}
		wait, stop := context.WithTimeout(ctx, 3*time.Second)
		p, e := c.ReceiveDatagram(wait)
		stop()
		if e != nil || !bytes.Equal(p, reply) {
			b.Fatal("echo", e)
		}
	}
}

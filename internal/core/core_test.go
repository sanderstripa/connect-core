package core_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/sanderstripa/connect-core/internal/core"
	"github.com/sanderstripa/connect-core/internal/lab"
)

type fixture struct {
	address      string
	clientTLS    *tls.Config
	serverTLS    *tls.Config
	serverConfig core.Config
	cancel       context.CancelFunc
}

func setup(t testing.TB) fixture {
	t.Helper()
	s, c, err := lab.Generate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	st, err := core.TLS(s, true)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := core.TLS(c, false)
	if err != nil {
		t.Fatal(err)
	}
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	t.Cleanup(func() { echo.Close() })
	go func() {
		for {
			conn, e := echo.Accept()
			if e != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "vertical chain works\n") }))
	t.Cleanup(httpServer.Close)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- core.Serve(ctx, listener, st, map[string]string{"echo": echo.Addr().String(), "http": httpServer.Listener.Addr().String()})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case e := <-done:
			if e != nil {
				t.Error(e)
			}
		case <-time.After(3 * time.Second):
			t.Error("server failed to stop")
		}
	})
	return fixture{listener.Addr().String(), ct, st, s, cancel}
}

func TestVerticalHTTP(t *testing.T) {
	f := setup(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- core.Forward(ctx, listener, f.address, "http", f.clientTLS) }()
	defer func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("forwarder failed to stop")
		}
	}()
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 5 * time.Second}
	defer client.CloseIdleConnections()
	response, err := client.Get("http://" + listener.Addr().String() + "/test")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	b, err := io.ReadAll(response.Body)
	if err != nil || string(b) != "vertical chain works\n" {
		t.Fatalf("%q %v", b, err)
	}
	t.Log("HTTP -> local forwarder -> TLS 1.3 + mTLS -> CONNECT server -> HTTP target: OK")
}

func TestSecurityFailures(t *testing.T) {
	f := setup(t)
	for _, tc := range []struct {
		name    string
		edit    func(*tls.Config)
		service string
	}{
		{"wrong-root", func(c *tls.Config) { c.RootCAs = x509.NewCertPool() }, "echo"},
		{"wrong-server-name", func(c *tls.Config) { c.ServerName = "invalid.example" }, "echo"},
		{"expired-server-cert", func(c *tls.Config) { c.Time = func() time.Time { return time.Now().Add(48 * time.Hour) } }, "echo"},
		{"missing-client-cert", func(c *tls.Config) { c.Certificates = nil }, "echo"},
		{"wrong-ALPN", func(c *tls.Config) { c.NextProtos = []string{"unrelated/1"} }, "echo"},
		{"unknown-service", func(c *tls.Config) {}, "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := f.clientTLS.Clone()
			tc.edit(c)
			conn, err := core.Dial(context.Background(), f.address, tc.service, c)
			if conn != nil {
				conn.Close()
			}
			if err == nil {
				t.Fatal("unexpected connection")
			}
		})
	}
	// A CA-valid leaf still needs an explicit fingerprint allowlist entry.
	cfg := f.serverConfig
	cfg.AllowedClients = []string{core.Fingerprint([]byte("unapproved certificate"))}
	st, err := core.TLS(cfg, true)
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- core.Serve(ctx, l, st, map[string]string{"echo": f.address}) }()
	defer func() { cancel(); <-done }()
	conn, err := core.Dial(context.Background(), l.Addr().String(), "echo", f.clientTLS)
	if conn != nil {
		conn.Close()
	}
	if err == nil {
		t.Fatal("revoked client accepted")
	}
}

func TestProtocolRejectsMalformed(t *testing.T) {
	cases := [][]byte{nil, []byte("CCP0"), {'C', 'C', 'P', '0', 2, 1, 0, 1, 'x'}, {'C', 'C', 'P', '0', 1, 2, 0, 1, 'x'}, {'C', 'C', 'P', '0', 1, 1, 255, 255}, {'C', 'C', 'P', '0', 1, 1, 0, 0}, {'C', 'C', 'P', '0', 1, 1, 0, 2, 'x'}, {'C', 'C', 'P', '0', 1, 1, 0, 1, '/'}}
	for _, b := range cases {
		if _, e := core.ReadRequest(bytes.NewReader(b)); e == nil {
			t.Fatalf("accepted %x", b)
		}
	}
	for _, a := range []string{"example.com:443", "0.0.0.0:443", "192.168.1.1:443", "[::]:443"} {
		if core.Loopback(a) == nil {
			t.Fatalf("accepted %s", a)
		}
	}
}

func TestConcurrentBinaryAndHalfClose(t *testing.T) {
	f := setup(t)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := core.Dial(context.Background(), f.address, "echo", f.clientTLS)
			if err != nil {
				t.Error(err)
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			payload := bytes.Repeat([]byte{0, 255, 2, 13, 10, 17}, 4096)
			if _, err = conn.Write(payload); err != nil {
				t.Error(err)
				return
			}
			if err = conn.(*tls.Conn).CloseWrite(); err != nil {
				t.Error(err)
				return
			}
			got, err := io.ReadAll(conn)
			if err != nil || !bytes.Equal(got, payload) {
				t.Errorf("binary/half-close: bytes=%d err=%v", len(got), err)
			}
		}()
	}
	wg.Wait()
}

func TestCancellationClosesActiveConnection(t *testing.T) {
	f := setup(t)
	conn, err := core.Dial(context.Background(), f.address, "echo", f.clientTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	f.cancel()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var b [1]byte
	_, err = conn.Read(b[:])
	if err == nil {
		t.Fatal("active connection stayed open")
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("cancellation did not close connection")
	}
}

func BenchmarkTunnelEcho(b *testing.B) {
	f := setup(b)
	conn, err := core.Dial(context.Background(), f.address, "echo", f.clientTLS)
	if err != nil {
		b.Fatal(err)
	}
	defer conn.Close()
	payload := make([]byte, 64*1024)
	got := make([]byte, len(payload))
	b.SetBytes(int64(len(payload) * 2))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err = conn.Write(payload); err != nil {
			b.Fatal(err)
		}
		if _, err = io.ReadFull(conn, got); err != nil {
			b.Fatal(err)
		}
	}
}

func FuzzReadRequest(f *testing.F) {
	f.Add([]byte{'C', 'C', 'P', '0', 1, 1, 0, 4, 'e', 'c', 'h', 'o'})
	f.Add([]byte("invalid"))
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = core.ReadRequest(bytes.NewReader(data)) })
}

func TestLatencyAndReconnectSmoke(t *testing.T) {
	f := setup(t)
	conn, err := core.Dial(context.Background(), f.address, "echo", f.clientTLS)
	if err != nil {
		t.Fatal(err)
	}
	if conn.(*tls.Conn).ConnectionState().Version != tls.VersionTLS13 {
		t.Fatal("expected TLS 1.3")
	}
	rtts := make([]time.Duration, 100)
	var got [64]byte
	payload := make([]byte, 64)
	for i := range rtts {
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		start := time.Now()
		if _, err = conn.Write(payload); err != nil {
			t.Fatal(err)
		}
		if _, err = io.ReadFull(conn, got[:]); err != nil {
			t.Fatal(err)
		}
		rtts[i] = time.Since(start)
	}
	conn.Close()
	sort.Slice(rtts, func(i, j int) bool { return rtts[i] < rtts[j] })
	t.Logf("loopback 64-byte echo RTT: p50=%s p95=%s p99=%s", rtts[49], rtts[94], rtts[98])
	for i := 0; i < 100; i++ {
		c, e := core.Dial(context.Background(), f.address, "echo", f.clientTLS)
		if e != nil {
			t.Fatalf("reconnect %d: %v", i, e)
		}
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, e = c.Write(payload); e != nil {
			c.Close()
			t.Fatal(e)
		}
		if _, e = io.ReadFull(c, got[:]); e != nil {
			c.Close()
			t.Fatal(e)
		}
		c.Close()
	}
	t.Log("100 independent connections with verified echo completed")
}

func TestMalformedRequestOverTLS(t *testing.T) {
	f := setup(t)
	c, e := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", f.address, f.clientTLS)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	_, e = c.Write([]byte{'C', 'C', 'P', '0', 1, 1, 255, 255})
	if e != nil {
		t.Fatal(e)
	}
	var b [1]byte
	_, e = c.Read(b[:])
	if e == nil {
		t.Fatal("oversized service accepted")
	}
	if ne, ok := e.(net.Error); ok && ne.Timeout() {
		t.Fatal("malformed request did not close promptly")
	}
}

func TestConfigBoundary(t *testing.T) {
	for _, raw := range []string{`{"config_version":2}`, `{"config_version":1,"unknown":true}`, `{"config_version":1} {}`, `{"config_version":1}` + string(bytes.Repeat([]byte(" "), 65536))} {
		p := filepath.Join(t.TempDir(), "config.json")
		if e := os.WriteFile(p, []byte(raw), 0600); e != nil {
			t.Fatal(e)
		}
		if _, e := core.Load(p); e == nil {
			t.Fatal("invalid/oversized config accepted")
		}
	}
}

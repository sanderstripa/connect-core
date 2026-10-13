//go:build windows

package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"github.com/quic-go/quic-go"
	"github.com/sanderstripa/connect-core/internal/desktop"
	"github.com/sanderstripa/connect-core/internal/ipvpn"
	"github.com/sanderstripa/connect-core/internal/lab"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type echoDevice struct{ *packetDevice }

func (d echoDevice) Write(b []byte) (int, error) {
	p := append([]byte(nil), b...)
	copy(p[12:16], b[16:20])
	copy(p[16:20], b[12:16])
	copy(p[20:22], b[22:24])
	copy(p[22:24], b[20:22])
	p[10] = 0
	p[11] = 0
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(p[i:]))
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(p[10:], ^uint16(sum))
	select {
	case d.packets <- p:
		return len(b), nil
	case <-d.done:
		return 0, io.EOF
	}
}
func wait(t *testing.T, w *worker, condition func(*worker) bool) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		w.mu.Lock()
		ok := condition(w)
		w.mu.Unlock()
		if ok {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("worker state deadline")
}
func TestRealIPV2WorkerLifecycle(t *testing.T) {
	dir := t.TempDir()
	server, client, e := lab.Generate(dir)
	if e != nil {
		t.Fatal(e)
	}
	sc := ipvpn.Config{Version: 2, Environment: "isolated-lab", Endpoint: "127.0.0.1:17444", Interface: "ccip0", Clients: map[string]string{server.AllowedClients[0]: "10.231.0.2"}, Destinations: []string{"10.232.0.1/32"}, Trust: server}
	tls, e := ipvpn.TLS(sc, true)
	if e != nil {
		t.Fatal(e)
	}
	listener, e := quic.ListenAddr("127.0.0.1:0", tls, ipvpn.QUIC())
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	policy, e := sc.Validate(true)
	if e != nil {
		t.Fatal(e)
	}
	go func() { done <- ipvpn.Serve(ctx, listener, echoDevice{newDevice()}, policy, &ipvpn.Stats{}) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("server did not stop")
		}
	}()
	cc := sc
	cc.Endpoint = listener.Addr().String()
	cc.Clients = nil
	cc.DeviceIP = "10.231.0.2"
	cc.Trust = client
	raw, _ := json.Marshal(cc)
	path := filepath.Join(dir, "ip-client.json")
	os.WriteFile(path, raw, 0600)
	b, e := load(path)
	if e != nil {
		t.Fatal(e)
	}
	w := &worker{b: b, writer: io.Discard, state: desktop.Ready}
	defer w.stop()
	for i := 0; i < 3; i++ {
		w.connect()
		wait(t, w, func(w *worker) bool { return w.state == desktop.Connected })
		w.probe()
		wait(t, w, func(w *worker) bool { return w.stats.SentBytes.Load() == 44 && w.stats.ReceivedBytes.Load() == 44 })
		w.stop()
		if w.state != desktop.Ready {
			t.Fatal("not ready after disconnect")
		}
	}
	w.b.Config.Trust.ServerName = "wrong.invalid"
	w.connect()
	wait(t, w, func(w *worker) bool { return w.state == desktop.Failed })
	w.stop()
	w.b = b
	w.connect()
	wait(t, w, func(w *worker) bool { return w.state == desktop.Connected })
	cancel()
	wait(t, w, func(w *worker) bool { return w.state == desktop.Failed })
}
func TestEncryptedBundleAndInvalidImport(t *testing.T) {
	_, client, e := lab.Generate(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	cfg := ipvpn.Config{Version: 2, Environment: "isolated-lab", Endpoint: "127.0.0.1:17444", Interface: "ccip0", DeviceIP: "10.231.0.2", Destinations: []string{"10.232.0.1/32"}, Trust: client}
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	raw, _ := json.Marshal(cfg)
	os.WriteFile(path, raw, 0600)
	b, e := load(path)
	if e != nil {
		t.Fatal(e)
	}
	saved := filepath.Join(dir, "saved.dpapi")
	if e = save(saved, b); e != nil {
		t.Fatal(e)
	}
	sealed, _ := os.ReadFile(saved)
	if json.Valid(sealed) {
		t.Fatal("plaintext saved")
	}
	plain, e := protect(sealed, true)
	if e != nil {
		t.Fatal(e)
	}
	var restored bundle
	if json.Unmarshal(plain, &restored) != nil || string(restored.Key) != string(b.Key) {
		t.Fatal("credential round trip")
	}
	sealed[len(sealed)/2] ^= 1
	if _, e = protect(sealed, true); e == nil {
		t.Fatal("tampered DPAPI accepted")
	}
	os.WriteFile(path, append(raw, []byte(" {}")...), 0600)
	if _, e = load(path); e == nil {
		t.Fatal("trailing config accepted")
	}
	cfg.Trust.Key = cfg.Trust.Cert
	raw, _ = json.Marshal(cfg)
	os.WriteFile(path, raw, 0600)
	if _, e = load(path); e == nil {
		t.Fatal("invalid key accepted")
	}
}

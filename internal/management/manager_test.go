package management

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"github.com/sanderstripa/connect-core/internal/core"
	"github.com/sanderstripa/connect-core/internal/ipvpn"
	"github.com/sanderstripa/connect-core/internal/lab"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type memoryTUN struct {
	read, write chan []byte
	done        chan struct{}
	once        sync.Once
}

func newTUN() *memoryTUN {
	return &memoryTUN{make(chan []byte, 8), make(chan []byte, 8), make(chan struct{}), sync.Once{}}
}
func (d *memoryTUN) Read(b []byte) (int, error) {
	select {
	case p := <-d.read:
		return copy(b, p), nil
	case <-d.done:
		return 0, io.EOF
	}
}
func (d *memoryTUN) Write(b []byte) (int, error) {
	select {
	case d.write <- append([]byte{}, b...):
		return len(b), nil
	case <-d.done:
		return 0, io.EOF
	}
}
func (d *memoryTUN) Close() error { d.once.Do(func() { close(d.done) }); return nil }
func fixture(t *testing.T) (*Manager, core.Config, string) {
	t.Helper()
	dir := t.TempDir()
	s, c, e := lab.Generate(dir)
	if e != nil {
		t.Fatal(e)
	}
	pc, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	endpoint := pc.LocalAddr().String()
	pc.Close()
	cfg := ipvpn.Config{Version: 2, Environment: "isolated-lab", Endpoint: endpoint, Interface: "ccip0", Clients: map[string]string{s.AllowedClients[0]: "10.231.0.2"}, Destinations: []string{"10.232.0.1/32"}, Trust: s}
	id := s.AllowedClients[0]
	path := filepath.Join(dir, "state.json")
	if e = WriteJSON(path, State{Version: 1, Config: cfg, Devices: map[string]Device{id: {ID: id, Name: "actual device", IP: "10.231.0.2", Access: "enabled"}}}); e != nil {
		t.Fatal(e)
	}
	m, e := New(path)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { m.Stop() })
	return m, c, id
}
func packet() []byte {
	p := make([]byte, 32)
	p[0] = 0x45
	p[8] = 64
	p[9] = 17
	binary.BigEndian.PutUint16(p[2:4], 32)
	copy(p[12:16], []byte{10, 231, 0, 2})
	copy(p[16:20], []byte{10, 232, 0, 1})
	binary.BigEndian.PutUint16(p[24:26], 12)
	copy(p[28:], "real")
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(p[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(p[10:12], ^uint16(sum))
	return p
}
func TestManagedRealQUICRevocationAndRestart(t *testing.T) {
	m, c, id := fixture(t)
	tun := newTUN()
	m.open = func(string) (ipvpn.Device, error) { return tun, nil }
	if e := m.Start(); e != nil {
		t.Fatal(e)
	}
	ct, e := ipvpn.TLS(ipvpn.Config{Trust: c}, false)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	q, e := ipvpn.Dial(ctx, m.state.Config.Endpoint, ct, netip.MustParseAddr("10.231.0.2"))
	if e != nil {
		t.Fatal(e)
	}
	if e = q.SendDatagram(packet()); e != nil {
		t.Fatal(e)
	}
	select {
	case p := <-tun.write:
		if string(p[28:]) != "real" {
			t.Fatal("payload corruption")
		}
	case <-ctx.Done():
		t.Fatal("no real packet")
	}
	deadline := time.Now().Add(time.Second)
	for m.control.Snapshot()[id].Received != 32 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if u := m.control.Snapshot()[id]; !u.Connected || u.Received != 32 {
		t.Fatalf("real counters missing: %+v", u)
	}
	if e = m.Change(id, "revoke", ""); e != nil {
		t.Fatal(e)
	}
	select {
	case <-q.Context().Done():
	case <-ctx.Done():
		t.Fatal("active QUIC connection not closed")
	}
	if _, e = ipvpn.Dial(ctx, m.state.Config.Endpoint, ct, netip.MustParseAddr("10.231.0.2")); e == nil {
		t.Fatal("revoked reconnect accepted")
	}
	m.Stop()
	reloaded, e := New(m.path)
	if e != nil {
		t.Fatal(e)
	}
	tun2 := newTUN()
	reloaded.open = func(string) (ipvpn.Device, error) { return tun2, nil }
	if e = reloaded.Start(); e != nil {
		t.Fatal(e)
	}
	defer reloaded.Stop()
	if _, e = ipvpn.Dial(ctx, reloaded.state.Config.Endpoint, ct, netip.MustParseAddr("10.231.0.2")); e == nil {
		t.Fatal("revocation lost after restart")
	}
}
func TestPersistenceFailureNeverReturnsSuccess(t *testing.T) {
	m, _, id := fixture(t)
	m.path = filepath.Join(t.TempDir(), "missing", "state.json")
	if m.Change(id, "disable", "") == nil {
		t.Fatal("false persistence success")
	}
	if _, ok := m.control.Policy(id); ok {
		t.Fatal("did not fail closed")
	}
}
func TestStoppedSettingsAndExportCompatibility(t *testing.T) {
	m, c, id := fixture(t)
	b, e := m.Export(id)
	if e != nil {
		t.Fatal(e)
	}
	var cfg ipvpn.Config
	if e = json.Unmarshal(b, &cfg); e != nil {
		t.Fatal(e)
	}
	if _, e = cfg.Validate(false); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(b), c.Key) || cfg.Trust.Key != "device-key.pem" || cfg.Trust.ServerName != "localhost" {
		t.Fatal("unsafe/incompatible export")
	}
	cfg.Trust.CA = c.CA
	cfg.Trust.Cert = c.Cert
	cfg.Trust.Key = c.Key
	if _, e = ipvpn.TLS(cfg, false); e != nil {
		t.Fatal(e)
	}
	if e = m.Configure(Settings{Endpoint: "0.0.0.0:443", Interface: "ccip0", Destinations: []string{"10.232.0.1/32"}}); e == nil {
		t.Fatal("public config accepted")
	}
	if e = m.Change(id, "delete", ""); e != nil {
		t.Fatal(e)
	}
	r, e := New(m.path)
	if e != nil {
		t.Fatal(e)
	}
	if _, ok := r.control.Policy(id); ok {
		t.Fatal("deleted access revived")
	}
	if len(r.Snapshot()["devices"].([]Device)) != 0 {
		t.Fatal("tombstone visible")
	}
}
func TestCSRProofAndTrust(t *testing.T) {
	m, c, id := fixture(t)
	keyPEM, e := os.ReadFile(c.Key)
	if e != nil {
		t.Fatal(e)
	}
	block, _ := pem.Decode(keyPEM)
	key, e := x509.ParsePKCS8PrivateKey(block.Bytes)
	if e != nil {
		t.Fatal(e)
	}
	cert, e := os.ReadFile(c.Cert)
	if e != nil {
		t.Fatal(e)
	}
	challenge := Random()
	makeCSR := func(k any, cn string) string {
		raw, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, k)
		if e != nil {
			t.Fatal(e)
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: raw}))
	}
	// Simulate a valid externally issued cert not previously bound in state.
	delete(m.state.Devices, id)
	delete(m.state.Config.Clients, id)
	enrollment := Enrollment{Name: "Verified device", IP: "10.231.0.3", CSR: makeCSR(key, challenge), Certificate: string(cert), Challenge: challenge}
	_, foreign, _ := ed25519.GenerateKey(rand.Reader)
	bad := enrollment
	bad.CSR = makeCSR(foreign, challenge)
	if _, e = m.Enroll(bad); e == nil {
		t.Fatal("foreign key accepted")
	}
	bad = enrollment
	bad.Challenge = Random()
	if _, e = m.Enroll(bad); e == nil {
		t.Fatal("wrong challenge accepted")
	}
	_, other, e := lab.Generate(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	foreignCert, _ := os.ReadFile(other.Cert)
	bad = enrollment
	bad.Certificate = string(foreignCert)
	foreignPEM, _ := os.ReadFile(other.Key)
	foreignBlock, _ := pem.Decode(foreignPEM)
	foreignKey, err := x509.ParsePKCS8PrivateKey(foreignBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	bad.CSR = makeCSR(foreignKey, challenge)
	if _, e = m.Enroll(bad); e == nil {
		t.Fatal("foreign certificate accepted")
	}
	got, e := m.Enroll(enrollment)
	if e != nil || got != id {
		t.Fatalf("valid proof: %s %v", got, e)
	}
	if _, e = m.Enroll(enrollment); e == nil {
		t.Fatal("duplicate certificate accepted")
	}
	if e = m.Change(id, "revoke", ""); e != nil {
		t.Fatal(e)
	}
	if _, e = m.Enroll(enrollment); e == nil {
		t.Fatal("revoked certificate re-enrolled")
	}
}

func TestHotEnrollmentAndExportedClientConnect(t *testing.T) {
	m, c, original := fixture(t)
	// Begin with a different allowed pin. The existing trusted cert/key pair is
	// a real, externally issued client identity, initially absent from this server.
	seed := Random()
	delete(m.state.Devices, original)
	delete(m.state.Config.Clients, original)
	m.state.Config.Clients[seed] = "10.231.0.2"
	m.state.Devices[seed] = Device{ID: seed, Name: "seed binding", IP: "10.231.0.2", Access: "enabled"}
	if e := WriteJSON(m.path, m.state); e != nil {
		t.Fatal(e)
	}
	fresh, e := New(m.path)
	if e != nil {
		t.Fatal(e)
	}
	tun := newTUN()
	fresh.open = func(string) (ipvpn.Device, error) { return tun, nil }
	defer fresh.Stop()
	if e = fresh.Start(); e != nil {
		t.Fatal(e)
	}
	ct, e := ipvpn.TLS(ipvpn.Config{Trust: c}, false)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, e = ipvpn.Dial(ctx, fresh.state.Config.Endpoint, ct, netip.MustParseAddr("10.231.0.3")); e == nil {
		t.Fatal("unenrolled trusted client connected")
	}
	keyPEM, _ := os.ReadFile(c.Key)
	block, _ := pem.Decode(keyPEM)
	key, e := x509.ParsePKCS8PrivateKey(block.Bytes)
	if e != nil {
		t.Fatal(e)
	}
	challenge := Random()
	raw, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: challenge}}, key)
	if e != nil {
		t.Fatal(e)
	}
	cert, _ := os.ReadFile(c.Cert)
	id, e := fresh.Enroll(Enrollment{Name: "CSR verified", IP: "10.231.0.3", CSR: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: raw})), Certificate: string(cert), Challenge: challenge})
	if e != nil {
		t.Fatal(e)
	}
	exported, e := fresh.Export(id)
	if e != nil {
		t.Fatal(e)
	}
	var cfg ipvpn.Config
	if e = json.Unmarshal(exported, &cfg); e != nil {
		t.Fatal(e)
	}
	cfg.Trust.CA = c.CA
	cfg.Trust.Cert = c.Cert
	cfg.Trust.Key = c.Key
	tlsConfig, e := ipvpn.TLS(cfg, false)
	if e != nil {
		t.Fatal(e)
	}
	q, e := ipvpn.Dial(ctx, cfg.Endpoint, tlsConfig, netip.MustParseAddr(cfg.DeviceIP))
	if e != nil {
		t.Fatal("hot enrollment/export failed", e)
	}
	defer q.CloseWithError(0, "test done")
	if !fresh.control.Snapshot()[id].Connected {
		t.Fatal("no actual enrolled session")
	}
}

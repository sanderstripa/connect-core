package management

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"github.com/sanderstripa/connect-core/internal/ipvpn"
	"github.com/sanderstripa/connect-core/internal/onboarding"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func brokerFixture(t *testing.T) (*Manager, *Broker, string) {
	t.Helper()
	dir := t.TempDir()
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	origin := "https://" + ln.Addr().String()
	state, e := Bootstrap(filepath.Join(dir, "keys"), "127.0.0.1:17444", origin)
	if e != nil {
		t.Fatal(e)
	}
	sp := filepath.Join(dir, "state.json")
	if e = WriteJSON(sp, state); e != nil {
		t.Fatal(e)
	}
	m, e := New(sp)
	if e != nil {
		t.Fatal(e)
	}
	broker, e := NewBroker(m, filepath.Join(dir, "invitations.json"), origin, filepath.Join(dir, "keys", "enrollment.pem"), filepath.Join(dir, "keys", "ca-key.pem"))
	if e != nil {
		t.Fatal(e)
	}
	pair, e := tls.LoadX509KeyPair(filepath.Join(dir, "keys", "enrollment.pem"), filepath.Join(dir, "keys", "enrollment-key.pem"))
	if e != nil {
		t.Fatal(e)
	}
	srv := &http.Server{Handler: &RegistrationAPI{Broker: broker, Host: ln.Addr().String()}, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}}}
	go srv.ServeTLS(ln, "", "")
	t.Cleanup(func() { srv.Close() })
	return m, broker, dir
}
func TestConnectLinkRealHTTPSApprovalKeyIsolationAndRestart(t *testing.T) {
	m, b, dir := brokerFixture(t)
	invite, e := b.Create("Actual enrolled client", "10.231.0.2")
	if e != nil {
		t.Fatal(e)
	}
	if !strings.HasPrefix(invite["link"], "connect://enroll?") || !strings.HasPrefix(invite["qr_png"], "iVBOR") {
		t.Fatal("real link/QR missing")
	}
	client, e := onboarding.NewClient(invite["link"], filepath.Join(dir, "client"))
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if ready, e := client.Poll(ctx); e != nil || ready {
		t.Fatalf("unapproved certificate: %v %v", ready, e)
	}
	other, e := onboarding.NewClient(invite["link"], filepath.Join(dir, "foreign"))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = other.Poll(ctx); e == nil {
		t.Fatal("one-time link bound to second key")
	}
	if e = b.Approve(invite["id"], Random()); e == nil {
		t.Fatal("wrong fingerprint approved")
	}
	// Reload both persisted state machines before approval and after issuance.
	reloaded, e := NewBroker(m, b.path, b.url, filepath.Join(dir, "keys", "enrollment.pem"), filepath.Join(dir, "keys", "ca-key.pem"))
	if e != nil {
		t.Fatal(e)
	}
	if e = reloaded.Approve(invite["id"], client.Fingerprint()); e != nil {
		t.Fatal(e)
	}
	b.mu.Lock()
	b.state = reloaded.state
	b.mu.Unlock()
	if ready, e := client.Poll(ctx); e != nil || !ready {
		t.Fatalf("approved export: %v %v", ready, e)
	}
	cfg, e := ipvpn.Load(filepath.Join(client.Dir, "connect-ip-client.json"))
	if e != nil {
		t.Fatal(e)
	}
	cfg.Trust.CA = filepath.Join(client.Dir, cfg.Trust.CA)
	cfg.Trust.Cert = filepath.Join(client.Dir, cfg.Trust.Cert)
	cfg.Trust.Key = filepath.Join(client.Dir, cfg.Trust.Key)
	if _, e = ipvpn.TLS(cfg, false); e != nil {
		t.Fatal(e)
	}
	key, _ := os.ReadFile(filepath.Join(client.Dir, "device-key.pem"))
	disk, _ := os.ReadFile(b.path)
	if strings.Contains(string(disk), client.Link.Token) || strings.Contains(string(disk), string(key)) {
		t.Fatal("token/private key persisted on server")
	}
	data, _ := json.Marshal(b.List())
	if strings.Contains(string(data), client.CSR) || strings.Contains(string(data), client.Link.Token) {
		t.Fatal("admin registry leaks onboarding bearer")
	}
	items := b.List()
	if items[0].Status != "approved" {
		t.Fatal("approval missing")
	}
	if e = m.Change(items[0].DeviceID, "revoke", ""); e != nil {
		t.Fatal(e)
	}
	if _, e = client.Poll(ctx); e == nil {
		t.Fatal("revoked credential retrieved as enabled")
	}
	if e = b.Approve(invite["id"], client.Fingerprint()); e == nil {
		t.Fatal("approved ticket replay reactivated access")
	}
	resumed, e := onboarding.ResumeClient(invite["link"], client.Dir)
	if e != nil || resumed.Fingerprint() != client.Fingerprint() {
		t.Fatal("client resume lost key")
	}
}
func TestInviteCancellationExpiryAndIssuerRecovery(t *testing.T) {
	m, b, dir := brokerFixture(t)
	invite, e := b.Create("Expiring", "10.231.0.3")
	if e != nil {
		t.Fatal(e)
	}
	client, e := onboarding.NewClient(invite["link"], filepath.Join(dir, "client"))
	if e != nil {
		t.Fatal(e)
	}
	b.mu.Lock()
	v := b.state.Items[invite["id"]]
	v.Expires = time.Now().Add(-time.Second)
	b.save(v)
	b.mu.Unlock()
	if _, e = b.Register(Registration{Token: client.Link.Token, CSR: client.CSR}); e == nil {
		t.Fatal("expired link registered")
	}
	invite, e = b.Create("Cancelled", "10.231.0.4")
	if e != nil {
		t.Fatal(e)
	}
	client, e = onboarding.NewClient(invite["link"], filepath.Join(dir, "second"))
	if e != nil {
		t.Fatal(e)
	}
	if e = b.Cancel(invite["id"]); e != nil {
		t.Fatal(e)
	}
	if _, e = b.Register(Registration{Token: client.Link.Token, CSR: client.CSR}); e == nil {
		t.Fatal("cancelled link registered")
	}
	invite, e = b.Create("Interrupted commit", "10.231.0.5")
	if e != nil {
		t.Fatal(e)
	}
	client, e = onboarding.NewClient(invite["link"], filepath.Join(dir, "third"))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = b.Register(Registration{Token: client.Link.Token, CSR: client.CSR}); e != nil {
		t.Fatal(e)
	}
	if e = b.Approve(invite["id"], client.Fingerprint()); e != nil {
		t.Fatal(e)
	}
	b.mu.Lock()
	v = b.state.Items[invite["id"]]
	v.Status = "issuing"
	b.save(v)
	b.mu.Unlock()
	if e = b.Approve(invite["id"], client.Fingerprint()); e != nil {
		t.Fatal("durable issuance recovery failed", e)
	}
	if len(m.Snapshot()["devices"].([]Device)) != 1 {
		t.Fatal("issuance duplicated a device")
	}
}

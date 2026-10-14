package management

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"github.com/sanderstripa/connect-core/internal/access"
	"github.com/sanderstripa/connect-core/internal/ipvpn"
	"github.com/sanderstripa/connect-core/internal/lab"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAutomaticInvitationTLSConsumptionAndRestart(t *testing.T) {
	dir := t.TempDir()
	server, _, e := lab.GenerateIssuance(dir)
	if e != nil {
		t.Fatal(e)
	}
	cfg := ipvpn.Config{Version: 2, Environment: "isolated-lab", Endpoint: "127.0.0.1:17444", Interface: "ccip0", Clients: map[string]string{server.AllowedClients[0]: "10.231.0.2"}, Destinations: []string{"10.232.0.1/32"}, Trust: server}
	path := filepath.Join(dir, "state.json")
	pin := server.AllowedClients[0]
	if e = WriteJSON(path, State{Version: 1, Config: cfg, Devices: map[string]Device{pin: {ID: pin, IP: "10.231.0.2", Name: "first", Access: "enabled"}}}); e != nil {
		t.Fatal(e)
	}
	m, e := New(path)
	if e != nil {
		t.Fatal(e)
	}
	s, e := NewIssuance(m, filepath.Join(dir, "issuer.key"), "https://127.0.0.1:1/enroll", server.Cert, server.Key)
	if e != nil {
		t.Fatal(e)
	}
	endpoint := httptest.NewUnstartedServer(s)
	pair, _ := tls.LoadX509KeyPair(server.Cert, server.Key)
	endpoint.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}}
	s.URL = "https://" + endpoint.Listener.Addr().String() + "/enroll"
	s.Host = endpoint.Listener.Addr().String()
	endpoint.StartTLS()
	defer endpoint.Close()
	link, e := s.Invite("new device", "10.231.0.3")
	if e != nil {
		t.Fatal(e)
	}
	i, e := access.Parse(link)
	if e != nil {
		t.Fatal(e)
	}
	key, csr, e := access.KeyAndCSR(i.Token)
	if e != nil {
		t.Fatal(e)
	}
	wrong := i
	wrong.Pin = strings.Repeat("0", 64)
	if _, e = access.Redeem(context.Background(), wrong, csr); e == nil {
		t.Fatal("wrong HTTPS pin accepted")
	}
	reply, e := access.Redeem(context.Background(), i, csr)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = tls.X509KeyPair([]byte(reply.Certificate), key); e != nil {
		t.Fatal(e)
	}
	if reply.Config.DeviceIP != "10.231.0.3" {
		t.Fatal("wrong device lease")
	}
	if _, e = access.Redeem(context.Background(), i, csr); e == nil {
		t.Fatal("one-use token reused")
	}
	disk, _ := os.ReadFile(path)
	if strings.Contains(string(disk), i.Token) || strings.Contains(string(disk), "PRIVATE KEY") {
		t.Fatal("token or private key persisted in server state")
	}
	restored, e := New(path)
	if e != nil {
		t.Fatal(e)
	}
	s.Manager = restored
	if _, e = s.Redeem(access.Request{Token: i.Token, CSR: csr}); e == nil {
		t.Fatal("consumed token revived after restart")
	}
	if len(restored.state.Devices) != 2 {
		t.Fatal("device binding missing")
	}
	for id, d := range restored.state.Devices {
		if d.IP == "10.231.0.3" {
			if e = restored.Change(id, "revoke", ""); e != nil {
				t.Fatal(e)
			}
			if _, e = restored.Export(id); e == nil {
				t.Fatal("revoked certificate exported")
			}
		}
	}
	bytes, _ := json.Marshal(reply)
	if strings.Contains(string(bytes), "PRIVATE KEY") {
		t.Fatal("server returned a private key")
	}
}

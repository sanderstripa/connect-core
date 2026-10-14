//go:build windows

package main

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/sanderstripa/connect-core/internal/desktop"
	"github.com/sanderstripa/connect-core/internal/ipvpn"
	"github.com/sanderstripa/connect-core/internal/lab"
	"github.com/sanderstripa/connect-core/internal/management"
)

func TestWorkerEnrollmentPersistsOnlyLocallyGeneratedKey(t *testing.T) {
	dir := t.TempDir()
	server, _, err := lab.GenerateIssuance(dir)
	if err != nil {
		t.Fatal(err)
	}
	pin := server.AllowedClients[0]
	cfg := ipvpn.Config{Version: 2, Environment: "isolated-lab", Endpoint: "127.0.0.1:17444", Interface: "ccip0", Clients: map[string]string{pin: "10.231.0.2"}, Destinations: []string{"10.232.0.1/32"}, Trust: server}
	state := filepath.Join(dir, "state.json")
	if err = management.WriteJSON(state, management.State{Version: 1, Config: cfg, Devices: map[string]management.Device{pin: {ID: pin, IP: "10.231.0.2", Name: "first", Access: "enabled"}}}); err != nil {
		t.Fatal(err)
	}
	m, err := management.New(state)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Stop()
	issuer, err := management.NewIssuance(m, filepath.Join(dir, "issuer.key"), "https://127.0.0.1:1/enroll", server.Cert, server.Key)
	if err != nil {
		t.Fatal(err)
	}
	https := httptest.NewUnstartedServer(issuer)
	pair, err := tls.LoadX509KeyPair(server.Cert, server.Key)
	if err != nil {
		t.Fatal(err)
	}
	https.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}}
	issuer.URL = "https://" + https.Listener.Addr().String() + "/enroll"
	issuer.Host = https.Listener.Addr().String()
	https.StartTLS()
	defer https.Close()
	link, err := issuer.Invite("desktop", "10.231.0.3")
	if err != nil {
		t.Fatal(err)
	}
	profile := filepath.Join(dir, "profile.dpapi")
	w := &worker{writer: io.Discard, state: desktop.Idle}
	defer w.stop()
	w.enroll(profile, link)
	wait(t, w, func(w *worker) bool { return w.state == desktop.Ready || w.state == desktop.Failed })
	w.mu.Lock()
	if w.code != 0 || w.b.Config.DeviceIP != "10.231.0.3" {
		w.mu.Unlock()
		t.Fatal("worker registration failed")
	}
	firstKey := string(w.b.Key)
	w.mu.Unlock()
	sealed, err := os.ReadFile(profile)
	if err != nil || json.Valid(sealed) {
		t.Fatal("profile missing or plaintext")
	}
	plain, err := protect(sealed, true)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plain)
	var saved bundle
	if err = json.Unmarshal(plain, &saved); err != nil {
		t.Fatal(err)
	}
	if string(saved.Key) != firstKey {
		t.Fatal("local key was replaced")
	}
	if _, err = saved.tls(); err != nil {
		t.Fatal("issued certificate does not match local key")
	}
	if _, err = os.Stat(profile + ".pending"); !os.IsNotExist(err) {
		t.Fatal("completed pending key retained")
	}
	w.enroll(profile, link)
	wait(t, w, func(w *worker) bool { return w.state == desktop.Failed })
	w.mu.Lock()
	if w.code != 4 || string(w.b.Key) != firstKey {
		w.mu.Unlock()
		t.Fatal("replayed invitation replaced device identity")
	}
	w.mu.Unlock()
}

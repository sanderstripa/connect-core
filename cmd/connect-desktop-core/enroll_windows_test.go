//go:build windows

package main

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sanderstripa/connect-core/internal/access"

	"github.com/sanderstripa/connect-core/internal/desktop"
	"github.com/sanderstripa/connect-core/internal/ipvpn"
	"github.com/sanderstripa/connect-core/internal/lab"
	"github.com/sanderstripa/connect-core/internal/management"
)

func TestCurrentPanelQRApprovalAndProtectedResume(t *testing.T) {
	dir := t.TempDir()
	api := &management.RegistrationAPI{}
	https := httptest.NewUnstartedServer(api)
	origin := "https://" + https.Listener.Addr().String()
	keys := filepath.Join(dir, "keys")
	state, err := management.Bootstrap(keys, "127.0.0.1:17444", origin)
	if err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(dir, "state.json")
	if err = management.WriteJSON(statePath, state); err != nil {
		t.Fatal(err)
	}
	m, err := management.New(statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Stop()
	broker, err := management.NewBroker(m, filepath.Join(dir, "invitations.json"), origin, filepath.Join(keys, "enrollment.pem"), filepath.Join(keys, "ca-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	api.Broker, api.Host = broker, https.Listener.Addr().String()
	pair, err := tls.LoadX509KeyPair(filepath.Join(keys, "enrollment.pem"), filepath.Join(keys, "enrollment-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	https.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}}
	https.StartTLS()
	defer https.Close()
	invite, err := broker.Create("Windows desktop", "10.231.0.2")
	if err != nil {
		t.Fatal(err)
	}
	png, err := base64.StdEncoding.DecodeString(invite["qr_png"])
	if err != nil {
		t.Fatal(err)
	}
	qrPath := filepath.Join(dir, "invite.png")
	if err = os.WriteFile(qrPath, png, 0600); err != nil {
		t.Fatal(err)
	}
	link, err := access.ReadQR(qrPath)
	if err != nil || link != invite["link"] {
		t.Fatalf("current panel QR is incompatible: %v", err)
	}
	w := &worker{writer: io.Discard}
	defer w.stop()
	profile := filepath.Join(dir, "profile.dpapi")
	w.enroll(profile, link)
	wait(t, w, func(w *worker) bool { return w.state == desktop.Enrolling && len(w.fingerprint) == 64 })
	w.mu.Lock()
	fingerprint := w.fingerprint
	w.mu.Unlock()
	deadline := time.Now().Add(8 * time.Second)
	var registered management.Invitation
	for time.Now().Before(deadline) {
		for _, v := range broker.List() {
			if v.Status == "pending" {
				registered = v
			}
		}
		if registered.Fingerprint != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if registered.Fingerprint != fingerprint {
		t.Fatal("displayed public fingerprint differs from panel")
	}
	w.stop() // Cancellation/reopening must not replace a token's bound identity.
	w.enroll(profile, link)
	wait(t, w, func(w *worker) bool { return w.state == desktop.Enrolling && len(w.fingerprint) == 64 })
	w.mu.Lock()
	resumed := w.fingerprint
	w.mu.Unlock()
	if resumed != fingerprint {
		t.Fatal("pending local key replaced on resume")
	}
	if err = broker.Approve(registered.ID, fingerprint); err != nil {
		t.Fatal(err)
	}
	wait(t, w, func(w *worker) bool { return w.state == desktop.Ready || w.state == desktop.Failed })
	w.mu.Lock()
	saved, code := w.b, w.code
	w.mu.Unlock()
	if code != 0 || saved.Config.DeviceIP != "10.231.0.2" {
		t.Fatal("approved registration failed")
	}
	if _, err = saved.tls(); err != nil {
		t.Fatal(err)
	}
	sealed, err := os.ReadFile(profile)
	if err != nil || json.Valid(sealed) {
		t.Fatal("approved profile missing or plaintext")
	}
	if _, err = os.Stat(profile + ".pending"); !os.IsNotExist(err) {
		t.Fatal("completed pending proof retained")
	}
}

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

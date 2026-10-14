//go:build windows

package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
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
	qrencoder "github.com/skip2/go-qrcode"
)

func TestCurrentPanelQRApprovalAndProtectedResume(t *testing.T) {
	dir := t.TempDir()
	api := &management.RegistrationAPI{}
	https := httptest.NewUnstartedServer(api)
	origin := "https://" + https.Listener.Addr().String()
	keys := filepath.Join(dir, "keys")
	// Export the actual endpoint before enrollment, without editing the issued
	// client configuration afterward. This tests the panel-to-engine contract.
	socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	endpoint := socket.LocalAddr().String()
	if err = socket.Close(); err != nil {
		t.Fatal(err)
	}
	state, err := management.Bootstrap(keys, endpoint, origin)
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
	legacyRaster, err := qrencoder.Encode(link, qrencoder.Medium, 384)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(qrPath, legacyRaster, 0600); err != nil {
		t.Fatal(err)
	}
	legacyLink, err := access.ReadQR(qrPath)
	if err != nil || legacyLink != link {
		t.Fatalf("existing fixed-size panel QR is incompatible: %v", err)
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
	// Use the approved certificate/address registry with PR #4's owned QUIC
	// listener, and the unmodified DPAPI bundle from the Windows importer.
	if err = management.ReadJSON(statePath, &state); err != nil {
		t.Fatal(err)
	}
	serverTLS, err := ipvpn.TLS(state.Config, true)
	if err != nil {
		t.Fatal(err)
	}
	listener, closeListener, err := ipvpn.Listen(endpoint, serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer closeListener()
	policies, err := state.Config.Validate(true)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- ipvpn.Serve(ctx, listener, echoDevice{newDevice()}, policies, &ipvpn.Stats{})
	}()
	defer func() {
		w.stop()
		cancel()
		closeListener()
		select {
		case err := <-serverDone:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("enrolled server shutdown stuck")
		}
	}()
	// Imported VPS profiles are ready with tunneled DNS. Do not invoke the
	// privileged networking helper on the unit-test host.
	if saved.Config.Network == nil || saved.Config.Network.Mode != "system-vpn" || saved.Config.Network.DNS != "1.1.1.1" {
		t.Fatal("managed import did not configure automatic tunneled DNS")
	}
	clientTLS, err := saved.tls()
	if err != nil {
		t.Fatal(err)
	}
	device := newDevice()
	stats := &ipvpn.Stats{}
	events := make(chan ipvpn.Event, 16)
	clientDone := make(chan error, 1)
	go func() {
		clientDone <- ipvpn.Managed(ctx, saved.Config, clientTLS, func(string) (ipvpn.Device, error) {
			return device, nil
		}, stats, func(e ipvpn.Event) { events <- e })
	}()
	defer func() {
		cancel()
		select {
		case err := <-clientDone:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("enrolled managed client shutdown stuck")
		}
	}()
	select {
	case event := <-events:
		if event.State != "authenticating" {
			t.Fatalf("unexpected first state: %s", event.State)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("managed client did not start")
	}
	select {
	case event := <-events:
		if event.State != "ready" {
			t.Fatalf("issued credentials rejected: %s", event.State)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("issued credentials failed to authenticate")
	}
	// This public-destination packet exists only in memory and encrypted
	// loopback QUIC; neither fixture forwards to the public Internet.
	packet := make([]byte, 28)
	packet[0], packet[8], packet[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(packet[2:], 28)
	copy(packet[12:16], []byte{10, 231, 0, 2})
	copy(packet[16:20], []byte{1, 1, 1, 1})
	binary.BigEndian.PutUint16(packet[20:], 49152)
	binary.BigEndian.PutUint16(packet[22:], 53)
	binary.BigEndian.PutUint16(packet[24:], 8)
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(packet[i:]))
	}
	for sum>>16 != 0 {
		sum = sum&65535 + sum>>16
	}
	binary.BigEndian.PutUint16(packet[10:], ^uint16(sum))
	device.packets <- packet
	deadline = time.Now().Add(3 * time.Second)
	for stats.ReceivedBytes.Load() != 28 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if stats.SentBytes.Load() != 28 || stats.ReceivedBytes.Load() != 28 {
		t.Fatal("issued export failed real CONNECT IP packet round trip")
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

package ipvpn

import (
	"bytes"
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func awaitState(t testing.TB, events <-chan Event, state string) {
	t.Helper()
	deadline := time.After(6 * time.Second)
	for {
		select {
		case e := <-events:
			if e.State == state {
				return
			}
		case <-deadline:
			t.Fatalf("state %s did not arrive", state)
		}
	}
}
func TestManagedServerRecoveryKeepsInterface(t *testing.T) {
	f := setup(t)
	cfg := Config{Version: 2, Environment: "isolated-lab", Endpoint: f.address, Interface: "ccip0", DeviceIP: "10.231.0.2", Destinations: []string{"10.232.0.1/32"}}
	native := newDevice()
	stats := &Stats{}
	var opens atomic.Int32
	events := make(chan Event, 16)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- Managed(ctx, cfg, f.tls, func(string) (Device, error) { opens.Add(1); return native, nil }, stats, func(e Event) { events <- e })
	}()
	defer func() {
		cancel()
		select {
		case e := <-done:
			if e != nil {
				t.Error(e)
			}
		case <-time.After(3 * time.Second):
			t.Error("managed shutdown stuck")
		}
	}()
	awaitState(t, events, "ready")
	p := udp("10.231.0.2", "10.232.0.1", []byte("before"))
	native.read <- p
	if !bytes.Equal(receive(t, f.device.write), p) {
		t.Fatal("initial packet")
	}
	f.cancel()
	_ = f.closeSocket()
	e := <-f.done
	f.done <- e
	awaitState(t, events, "reconnecting")
	select {
	case <-native.done:
		t.Fatal("interface removed on network loss")
	default:
	}
	native.read <- udp("10.231.0.2", "10.232.0.1", []byte("must-not-replay"))
	deadline := time.Now().Add(time.Second)
	for stats.Dropped.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if stats.Dropped.Load() == 0 {
		t.Fatal("disconnected packet not drained")
	}
	tls, e := TLS(f.server, true)
	if e != nil {
		t.Fatal(e)
	}
	l, closeSocket, e := Listen(f.address, tls)
	if e != nil {
		t.Fatal(e)
	}
	d := newDevice()
	policies, e := f.server.Validate(true)
	if e != nil {
		t.Fatal(e)
	}
	serverctx, stop := context.WithCancel(ctx)
	serverDone := make(chan error, 1)
	go func() { serverDone <- Serve(serverctx, l, d, policies, &Stats{}) }()
	defer func() {
		stop()
		_ = closeSocket()
		if e := <-serverDone; e != nil {
			t.Error(e)
		}
	}()
	awaitState(t, events, "ready")
	p = udp("10.231.0.2", "10.232.0.1", []byte("after"))
	native.read <- p
	if !bytes.Equal(receive(t, d.write), p) {
		t.Fatal("stale packets replayed or recovery corrupted")
	}
	reply := udp("10.232.0.1", "10.231.0.2", []byte("reply"))
	d.read <- reply
	if !bytes.Equal(receive(t, native.write), reply) {
		t.Fatal("recovery reply")
	}
	if opens.Load() != 1 {
		t.Fatal("native interface recreated")
	}
}
func TestManagedBadIdentityCreatesNoInterface(t *testing.T) {
	f := setup(t)
	ct := f.tls.Clone()
	ct.ServerName = "wrong.test"
	cfg := Config{Version: 2, Environment: "isolated-lab", Endpoint: f.address, Interface: "ccip0", DeviceIP: "10.231.0.2", Destinations: []string{"10.232.0.1/32"}}
	opened := false
	e := Managed(context.Background(), cfg, ct, func(string) (Device, error) { opened = true; return newDevice(), nil }, &Stats{}, nil)
	if e == nil || opened {
		t.Fatal("bad identity acquired TUN")
	}
}
func TestManagedViewDoesNotRemoveNativeOnClose(t *testing.T) {
	d := newDevice()
	h := newHub(d, &Stats{})
	defer h.close()
	v := h.session()
	done := make(chan error, 1)
	go func() { _, e := v.Read(make([]byte, 1100)); done <- e }()
	_ = v.Close()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("closed view read succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("view did not unblock")
	}
	select {
	case <-d.done:
		t.Fatal("session close removed native TUN")
	default:
	}
}
func TestManagedInitialCancellation(t *testing.T) {
	f := setup(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cfg := Config{Version: 2, Environment: "isolated-lab", Endpoint: f.address, Interface: "ccip0", DeviceIP: "10.231.0.2", Destinations: []string{"10.232.0.1/32"}}
	if e := Managed(ctx, cfg, f.tls, func(string) (Device, error) { t.Fatal("cancelled open"); return nil, nil }, &Stats{}, nil); e != nil {
		t.Fatal(e)
	}
}

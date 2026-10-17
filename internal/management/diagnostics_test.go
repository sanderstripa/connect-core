package management

import (
	"context"
	"encoding/json"
	"github.com/sanderstripa/connect-core/internal/ipvpn"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestDiagnosticRetentionAndNoSecrets(t *testing.T) {
	m, _, id := fixture(t)
	stats := &ipvpn.Stats{}
	stats.SendQueue.Observe(12 * time.Millisecond)
	for i := 0; i < diagnosticSamples+7; i++ {
		stats.Sent.Add(1)
		m.recordDiagnostic(stats)
	}
	report := m.Diagnostics()
	samples := report["samples"].([]DiagnosticSample)
	if len(samples) != diagnosticSamples || samples[0].Server["packets"].(map[string]uint64)["sent_packets"] != 8 {
		t.Fatal("history not bounded/newest")
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{id, m.path, m.state.Config.Endpoint, m.state.Config.Trust.Key, "certificate", "connect://", "token_file"} {
		if secret != "" && strings.Contains(string(data), secret) {
			t.Fatalf("diagnostics exposed private field %q", secret)
		}
	}
	if !strings.Contains(string(data), `"mean_us":null`) {
		t.Fatal("unsampled stage reported as measured zero")
	}
}

func TestDiagnosticActualTransportAndSamplerShutdown(t *testing.T) {
	m, c, _ := fixture(t)
	tun := newTUN()
	m.open = func(string) (ipvpn.Device, error) { return tun, nil }
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	ct, err := ipvpn.TLS(ipvpn.Config{Trust: c}, false)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	q, err := ipvpn.Dial(ctx, m.state.Config.Endpoint, ct, netip.MustParseAddr("10.231.0.2"))
	if err != nil {
		t.Fatal(err)
	}
	defer q.CloseWithError(0, "test done")
	for i := 0; i < 128; i++ {
		if err = q.SendDatagram(packet()); err != nil {
			t.Fatal(err)
		}
		select {
		case <-tun.write:
		case <-ctx.Done():
			t.Fatal("datagram not delivered")
		}
		reply := packet()
		copy(reply[12:16], []byte{10, 232, 0, 1})
		copy(reply[16:20], []byte{10, 231, 0, 2})
		select {
		case tun.read <- reply:
		case <-ctx.Done():
			t.Fatal("server TUN reply blocked")
		}
		if _, err = q.ReceiveDatagram(ctx); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(4 * time.Second)
	found := false
	for time.Now().Before(deadline) {
		samples := m.Diagnostics()["samples"].([]DiagnosticSample)
		for _, s := range samples {
			for _, tr := range s.Transports {
				if tr.Connected && tr.PacketsReceived > 0 && tr.Session != 0 {
					found = true
				}
			}
		}
		if found {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !found {
		t.Fatal("periodic history missing actual QUIC telemetry")
	}
	if err = m.Stop(); err != nil {
		t.Fatal(err)
	}
	samples := m.Diagnostics()["samples"].([]DiagnosticSample)
	last := samples[len(samples)-1]
	for _, name := range []string{"server_send_queue", "receive_queue", "quic_send", "tun_write"} {
		stage := last.Server["timings"].(map[string]any)[name].(map[string]any)
		if stage["samples"].(uint64) == 0 || stage["mean_us"] == nil {
			t.Fatalf("real server stage %s not sampled", name)
		}
	}
	if len(last.Transports) != 1 || last.Transports[0].Connected {
		t.Fatal("final transport statistics missing after shutdown")
	}
	count := len(samples)
	time.Sleep(30 * time.Millisecond)
	if len(m.Diagnostics()["samples"].([]DiagnosticSample)) != count {
		t.Fatal("sampler still active after shutdown")
	}
}

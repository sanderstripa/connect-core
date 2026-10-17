package management

import (
	"github.com/sanderstripa/connect-core/internal/ipvpn"
	"time"
)

const diagnosticSamples = 180

type DiagnosticSample struct {
	At           time.Time               `json:"at"`
	ProcessCPUUS *uint64                 `json:"process_cpu_us"`
	Server       map[string]any          `json:"server"`
	Transports   []ipvpn.TransportSample `json:"transports"`
}

func (m *Manager) recordDiagnostic(stats *ipvpn.Stats) {
	s := DiagnosticSample{At: time.Now().UTC(), Server: stats.DiagnosticSnapshot(), Transports: m.control.TransportSnapshot()}
	if value, ok := processCPUTime(); ok {
		s.ProcessCPUUS = &value
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	recent := make([]ipvpn.TransportSample, 0, len(s.Transports))
	for _, tr := range s.Transports {
		if !tr.At.Before(m.started) && (tr.Connected || s.At.Sub(tr.At) <= 6*time.Minute) {
			recent = append(recent, tr)
		}
	}
	s.Transports = recent
	if len(m.diagnostics) == diagnosticSamples {
		copy(m.diagnostics, m.diagnostics[1:])
		m.diagnostics = m.diagnostics[:diagnosticSamples-1]
	}
	m.diagnostics = append(m.diagnostics, s)
}

func (m *Manager) collectDiagnostics(done <-chan struct{}, stats *ipvpn.Stats) {
	m.recordDiagnostic(stats)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			m.recordDiagnostic(stats)
		}
	}
}

// Report is bounded and in memory. It intentionally excludes configuration,
// device identities, keys, invitations, endpoints and process/filesystem paths.
func (m *Manager) Diagnostics() map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	samples := append([]DiagnosticSample{}, m.diagnostics...)
	return map[string]any{"schema": 1, "core_version": Version, "generated_at": time.Now().UTC(), "server_started_at": m.started, "status": m.status, "interval_seconds": 2, "retention_samples": diagnosticSamples, "scope": "CONNECT server only; CPU is cumulative OS process time; timings cumulative sampled local waits; QUIC loss estimates may decrease after late acknowledgements; RTT is server-observed; stopped sessions retain their final sample", "timing_sample_every": 64, "samples": samples}
}

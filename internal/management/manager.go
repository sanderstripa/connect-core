package management

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/quic-go/quic-go"
	"github.com/sanderstripa/connect-core/internal/core"
	"github.com/sanderstripa/connect-core/internal/ipvpn"
	"net"
	"sync"
	"time"
)

type Device struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	IP          string `json:"ip"`
	Access      string `json:"access"`
	Certificate string `json:"certificate,omitempty"`
	ipvpn.Usage
}
type State struct {
	Version     int                         `json:"version"`
	Config      ipvpn.Config                `json:"config"`
	Devices     map[string]Device           `json:"devices"`
	Invitations map[string]InvitationRecord `json:"invitations,omitempty"`
}
type Manager struct {
	mu      sync.Mutex
	state   State
	path    string
	control *ipvpn.Control
	cancel  context.CancelFunc
	done    chan struct{}
	status  string
	started time.Time
	events  []string
	open    func(string) (ipvpn.Device, error)
}

func New(path string) (*Manager, error) {
	var s State
	if e := ReadJSON(path, &s); e != nil {
		return nil, e
	}
	if s.Version != 1 || s.Devices == nil {
		return nil, errors.New("unsupported state version")
	}
	policies, e := s.Config.Validate(true)
	if e != nil {
		return nil, e
	}
	for pin := range s.Config.Clients {
		d, ok := s.Devices[pin]
		if !ok || d.ID != pin || d.IP != s.Config.Clients[pin] || (d.Access != "enabled" && d.Access != "disabled" && d.Access != "revoked" && d.Access != "deleted") {
			return nil, errors.New("invalid device state")
		}
	}
	ctl := ipvpn.NewControl(policies)
	for pin, d := range s.Devices {
		if d.Access != "enabled" {
			ctl.Deny(pin)
		}
	}
	return &Manager{state: s, path: path, control: ctl, status: "stopped", open: ipvpn.Open, events: []string{}}, nil
}
func (m *Manager) event(s string) {
	m.events = append(m.events, time.Now().UTC().Format(time.RFC3339)+" "+s)
	if len(m.events) > 100 {
		m.events = m.events[len(m.events)-100:]
	}
}
func (m *Manager) UseOwnedTUN() error {
	if m.state.Config.Environment != "managed-vps" || m.state.Config.Interface != "cc-vps0" {
		return errors.New("managed VPS installer configuration required")
	}
	m.open = ipvpn.OpenOwned
	return nil
}
func (m *Manager) CheckTLS() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, e := ipvpn.TLS(m.state.Config, true)
	return e
}
func (m *Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.done != nil {
		return errors.New("server already active")
	}
	t, e := ipvpn.TLS(m.state.Config, true)
	if e != nil {
		m.status = "error"
		m.event("start failed: TLS configuration")
		return errors.New("TLS configuration failed")
	}
	// Keep normal CA/EKU verification. Check the mutable pin registry both here
	// and at admission; session tickets and 0-RTT remain disabled.
	t.VerifyConnection = func(s tls.ConnectionState) error {
		if len(s.PeerCertificates) == 0 {
			return errors.New("certificate required")
		}
		if _, ok := m.control.Policy(core.Fingerprint(s.PeerCertificates[0].Raw)); !ok {
			return errors.New("access denied")
		}
		return nil
	}
	pc, e := net.ListenPacket("udp", m.state.Config.Endpoint)
	if e != nil {
		m.status = "error"
		m.event("start failed: listener")
		return errors.New("data listener unavailable")
	}
	l, e := quic.Listen(pc, t, ipvpn.QUIC())
	if e != nil {
		_ = pc.Close()
		m.status = "error"
		m.event("start failed: listener")
		return errors.New("data listener unavailable")
	}
	d, e := m.open(m.state.Config.Interface)
	if e != nil {
		_ = l.Close()
		_ = pc.Close()
		m.status = "error"
		m.event("start failed: isolated TUN")
		if m.state.Config.Environment == "managed-vps" {
			return fmt.Errorf("installer-owned TUN unavailable: %w", e)
		}
		return errors.New("isolated TUN unavailable; check lab namespace and permissions")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	m.cancel = cancel
	m.done = done
	m.started = time.Now()
	m.status = "running"
	m.event("server started")
	go func() {
		err := ipvpn.ServeControlled(ctx, l, d, m.control, &ipvpn.Stats{})
		_ = pc.Close()
		m.mu.Lock()
		m.cancel = nil
		m.done = nil
		if err != nil {
			m.status = "error"
			m.event("server failed")
		} else {
			m.status = "stopped"
			m.event("server stopped")
		}
		m.mu.Unlock()
		close(done)
	}()
	return nil
}
func (m *Manager) Stop() error {
	m.mu.Lock()
	cancel, done := m.cancel, m.done
	if cancel != nil {
		m.status = "stopping"
		cancel()
	}
	m.mu.Unlock()
	if done != nil {
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			return errors.New("shutdown timed out; server is still stopping")
		}
	}
	return nil
}
func (m *Manager) Snapshot() map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	devices := []Device{}
	active := 0
	var rx, tx uint64
	usage := m.control.Snapshot()
	for id, d := range m.state.Devices {
		u := usage[id]
		rx += u.Received
		tx += u.Sent
		if u.Connected {
			active++
		}
		if d.Access == "deleted" {
			continue
		}
		d.Usage = u
		d.Certificate = ""
		devices = append(devices, d)
	}
	uptime := int64(0)
	if m.status == "running" || m.status == "stopping" {
		uptime = int64(time.Since(m.started).Seconds())
	}
	return map[string]any{"environment": m.state.Config.Environment, "device_network": m.state.Config.DeviceNetwork, "api_version": APIVersion, "core_version": Version, "protocol_version": 2, "transport": "QUIC DATAGRAM / TLS 1.3 mTLS", "status": m.status, "endpoint": m.state.Config.Endpoint, "interface": m.state.Config.Interface, "destinations": m.state.Config.Destinations, "uptime_seconds": uptime, "active_sessions": active, "received_bytes": rx, "sent_bytes": tx, "devices": devices, "metrics": SystemMetrics(), "capabilities": map[string]bool{"hot_revocation": true, "csr_enrollment": true, "qr_import": false, "core_update": false}}
}
func clone(s State) State {
	out := s
	out.Devices = map[string]Device{}
	for k, v := range s.Devices {
		out.Devices[k] = v
	}
	out.Config.Clients = map[string]string{}
	out.Invitations = map[string]InvitationRecord{}
	for k, v := range s.Invitations {
		out.Invitations[k] = v
	}
	for k, v := range s.Config.Clients {
		out.Config.Clients[k] = v
	}
	return out
}
func (m *Manager) Change(id, action, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.state.Devices[id]
	if !ok || d.Access == "deleted" {
		return errors.New("device not found")
	}
	next := clone(m.state)
	switch action {
	case "rename":
		if len(name) < 1 || len(name) > 80 {
			return errors.New("name must be 1..80 bytes")
		}
		d.Name = name
	case "disable":
		if d.Access == "revoked" {
			return errors.New("certificate already revoked")
		}
		d.Access = "disabled"
	case "revoke":
		d.Access = "revoked"
	case "delete":
		d.Access = "deleted"
		d.Name = ""
		d.Certificate = ""
	default:
		return errors.New("unsupported device action")
	}
	next.Devices[id] = d
	if action != "rename" {
		delete(next.Config.Clients, id)
	}
	if e := WriteJSON(m.path, next); e != nil { // Fail closed even if fsync outcome is ambiguous.
		if action != "rename" {
			m.control.Deny(id)
		}
		return errors.New("state persistence failed; access denied in memory")
	}
	m.state = next
	if action != "rename" {
		m.control.Deny(id)
	}
	m.event("device " + action)
	return nil
}

type Settings struct {
	Endpoint     string   `json:"endpoint"`
	Interface    string   `json:"interface"`
	Destinations []string `json:"destinations"`
}

func (m *Manager) Configure(s Settings) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state.Config.Environment == "managed-vps" {
		return errors.New("VPS network is installer-owned; change it through a reviewed installer transaction")
	}
	if m.done != nil {
		return errors.New("stop server before changing network settings")
	}
	next := clone(m.state)
	next.Config.Endpoint = s.Endpoint
	next.Config.Interface = s.Interface
	next.Config.Destinations = s.Destinations
	policies, e := next.Config.Validate(true)
	if e != nil {
		return e
	}
	if e = WriteJSON(m.path, next); e != nil {
		return e
	}
	m.state = next
	for pin, p := range policies {
		m.control.Add(pin, p)
	}
	m.event("network settings changed")
	return nil
}
func (m *Manager) Logs() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string{}, m.events...)
}

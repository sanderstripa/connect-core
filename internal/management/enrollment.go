package management

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/sanderstripa/connect-core/internal/core"
	"os"
)

type Enrollment struct {
	Name        string `json:"name"`
	IP          string `json:"ip"`
	CSR         string `json:"csr"`
	Certificate string `json:"certificate"`
	Challenge   string `json:"challenge"`
}

// The certificate is issued by an external CA. A fresh challenge-bearing,
// signed CSR proves possession of its private key. The authenticated operator
// must independently verify the physical device and approve its fingerprint.
func (m *Manager) Enroll(e Enrollment) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(e.Name) < 1 || len(e.Name) > 80 {
		return "", errors.New("invalid device name")
	}
	cb, rest := pem.Decode([]byte(e.Certificate))
	if cb == nil || cb.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return "", errors.New("one leaf certificate required")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil || cert.IsCA {
		return "", errors.New("invalid client leaf")
	}
	rb, rest := pem.Decode([]byte(e.CSR))
	if rb == nil || rb.Type != "CERTIFICATE REQUEST" || len(bytes.TrimSpace(rest)) != 0 {
		return "", errors.New("one CSR required")
	}
	csr, err := x509.ParseCertificateRequest(rb.Bytes)
	if err != nil || csr.CheckSignature() != nil || csr.Subject.CommonName != e.Challenge || len(e.Challenge) != 64 {
		return "", errors.New("CSR proof rejected")
	}
	if !bytes.Equal(csr.RawSubjectPublicKeyInfo, cert.RawSubjectPublicKeyInfo) {
		return "", errors.New("certificate does not belong to CSR key")
	}
	roots := x509.NewCertPool()
	ca, err := os.ReadFile(m.state.Config.Trust.CA)
	if err != nil || !roots.AppendCertsFromPEM(ca) {
		return "", errors.New("CA unavailable")
	}
	if _, err = cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return "", errors.New("client certificate trust or validity failed")
	}
	id := core.Fingerprint(cert.Raw)
	if _, exists := m.state.Devices[id]; exists {
		return "", errors.New("certificate already registered; revocations cannot be undone")
	}
	next := clone(m.state)
	next.Config.Clients[id] = e.IP
	policies, err := next.Config.Validate(true)
	if err != nil {
		return "", err
	}
	next.Devices[id] = Device{ID: id, Name: e.Name, IP: e.IP, Access: "enabled", Certificate: e.Certificate}
	if err = WriteJSON(m.path, next); err != nil {
		m.control.Deny(id)
		return "", errors.New("persistence failed")
	}
	m.state = next
	m.control.Add(id, policies[id])
	m.event("device enrolled after CSR proof")
	return id, nil
}
func (m *Manager) Export(id string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.state.Devices[id]
	if !ok || d.Access != "enabled" {
		return nil, errors.New("enabled device required")
	}
	// These are client-local paths. No private key is read or exported.
	cfg := m.state.Config
	cfg.Clients = nil
	cfg.DeviceIP = d.IP
	cfg.Trust.AllowedClients = nil
	cfg.Trust.Services = nil
	cfg.Trust.CA = "ca.pem"
	cfg.Trust.Cert = "device.pem"
	cfg.Trust.Key = "device-key.pem"
	serverPEM, err := os.ReadFile(m.state.Config.Trust.Cert)
	if err != nil {
		return nil, errors.New("server identity unavailable")
	}
	block, _ := pem.Decode(serverPEM)
	if block == nil {
		return nil, errors.New("invalid server identity")
	}
	server, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.New("invalid server identity")
	}
	if len(server.DNSNames) > 0 {
		cfg.Trust.ServerName = server.DNSNames[0]
	} else if len(server.IPAddresses) > 0 {
		cfg.Trust.ServerName = server.IPAddresses[0].String()
	} else {
		return nil, errors.New("server certificate requires SAN for client verification")
	}
	return json.MarshalIndent(cfg, "", "  ")
}
func (m *Manager) PublicCertificate(id string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.state.Devices[id]
	if !ok || d.Access != "enabled" {
		return "", errors.New("enabled device required")
	}
	if d.Certificate == "" {
		return "", errors.New("existing certificate was not imported; use original device certificate")
	}
	return d.Certificate, nil
}
func (m *Manager) CA() ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return os.ReadFile(m.state.Config.Trust.CA)
}

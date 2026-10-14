package management

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/sanderstripa/connect-core/internal/access"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"time"
)

type InvitationRecord struct {
	Name    string    `json:"name"`
	IP      string    `json:"ip"`
	Expires time.Time `json:"expires"`
}
type Issuance struct {
	Manager        *Manager
	signer         crypto.Signer
	ca             *x509.Certificate
	URL, Pin, Host string
	slots          chan struct{}
}

func digest(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

// The issuer is opt-in and supplied by the operator; it is never a browser key.
func NewIssuance(m *Manager, keyPath, endpoint, tlsCert, tlsKey string) (*Issuance, error) {
	u, e := url.Parse(endpoint)
	if e != nil {
		return nil, e
	}
	probe := access.Invitation{URL: endpoint, Pin: Random(), Token: Random()}
	if _, e = access.Link(probe); e != nil {
		return nil, e
	}
	pair, e := tls.LoadX509KeyPair(tlsCert, tlsKey)
	if e != nil {
		return nil, e
	}
	leaf, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil || leaf.VerifyHostname(u.Hostname()) != nil {
		return nil, errors.New("enrollment TLS identity mismatch")
	}
	f, e := os.Open(keyPath)
	if e != nil {
		return nil, errors.New("issuer key unavailable")
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Size() > 65536 {
		return nil, errors.New("issuer key unavailable")
	}
	raw, e := io.ReadAll(io.LimitReader(f, 65537))
	if e != nil || len(raw) > 65536 {
		return nil, errors.New("issuer key unavailable")
	}
	block, rest := pem.Decode(raw)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("one PKCS8 issuer key required")
	}
	key, e := x509.ParsePKCS8PrivateKey(block.Bytes)
	clear(raw)
	if e != nil {
		return nil, e
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("issuer cannot sign")
	}
	caPEM, e := m.CA()
	if e != nil {
		return nil, e
	}
	pub, e := x509.MarshalPKIXPublicKey(signer.Public())
	if e != nil {
		return nil, e
	}
	var ca *x509.Certificate
	for len(caPEM) > 0 {
		b, r := pem.Decode(caPEM)
		if b == nil {
			break
		}
		caPEM = r
		c, e := x509.ParseCertificate(b.Bytes)
		if e == nil && c.IsCA && c.BasicConstraintsValid && c.KeyUsage&x509.KeyUsageCertSign != 0 && bytes.Equal(c.RawSubjectPublicKeyInfo, pub) {
			ca = c
			break
		}
	}
	if ca == nil || time.Now().Before(ca.NotBefore) || time.Now().After(ca.NotAfter) {
		return nil, errors.New("issuer must match a current trusted CA")
	}
	return &Issuance{Manager: m, signer: signer, ca: ca, URL: endpoint, Pin: access.SPKI(leaf), Host: u.Host, slots: make(chan struct{}, 16)}, nil
}
func (s *Issuance) Invite(name, ip string) (string, error) {
	if len(name) < 1 || len(name) > 80 {
		return "", errors.New("invalid name")
	}
	m := s.Manager
	m.mu.Lock()
	defer m.mu.Unlock()
	next := clone(m.state)
	now := time.Now()
	if next.Invitations == nil {
		next.Invitations = map[string]InvitationRecord{}
	}
	for h, v := range next.Invitations {
		if now.After(v.Expires) {
			delete(next.Invitations, h)
		} else if v.IP == ip {
			return "", errors.New("address already reserved")
		}
	}
	if len(next.Invitations) >= 32 {
		return "", errors.New("too many outstanding invitations")
	}
	next.Config.Clients[Random()] = ip
	if _, e := next.Config.Validate(true); e != nil {
		return "", e
	}
	next = clone(m.state)
	if next.Invitations == nil {
		next.Invitations = map[string]InvitationRecord{}
	}
	for h, v := range next.Invitations {
		if now.After(v.Expires) {
			delete(next.Invitations, h)
		}
	}
	token := Random()
	next.Invitations[digest(token)] = InvitationRecord{Name: name, IP: ip, Expires: now.Add(5 * time.Minute)}
	if e := WriteJSON(m.path, next); e != nil {
		return "", errors.New("invitation persistence failed")
	}
	m.state = next
	m.event("one-use invitation created")
	return access.Link(access.Invitation{URL: s.URL, Pin: s.Pin, Token: token})
}
func (s *Issuance) Redeem(req access.Request) (access.Response, error) {
	var result access.Response
	if len(req.Token) != 64 || len(req.CSR) > 8192 {
		return result, errors.New("invalid enrollment")
	}
	block, rest := pem.Decode([]byte(req.CSR))
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(bytes.TrimSpace(rest)) != 0 {
		return result, errors.New("invalid CSR")
	}
	csr, e := x509.ParseCertificateRequest(block.Bytes)
	if e != nil || csr.CheckSignature() != nil || csr.Subject.CommonName != req.Token {
		return result, errors.New("CSR proof failed")
	}
	if _, ok := csr.PublicKey.(ed25519.PublicKey); !ok {
		return result, errors.New("Ed25519 device key required")
	}
	m := s.Manager
	m.mu.Lock()
	defer m.mu.Unlock()
	record, ok := m.state.Invitations[digest(req.Token)]
	if !ok || time.Now().After(record.Expires) {
		return result, errors.New("invitation expired or consumed")
	}
	// Consume durably BEFORE issuance. Crashes and lost replies require a fresh
	// operator-approved invitation; a token cannot mint a second certificate.
	next := clone(m.state)
	delete(next.Invitations, digest(req.Token))
	if e = WriteJSON(m.path, next); e != nil {
		return result, errors.New("invitation commit failed")
	}
	m.state = next
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		return result, e
	}
	end := time.Now().Add(24 * time.Hour)
	if s.ca.NotAfter.Before(end) {
		end = s.ca.NotAfter
	}
	if time.Until(end) < 5*time.Minute {
		return result, errors.New("issuer validity too short")
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: record.Name}, NotBefore: time.Now().Add(-30 * time.Second), NotAfter: end, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true}
	der, e := x509.CreateCertificate(rand.Reader, template, s.ca, csr.PublicKey, s.signer)
	if e != nil {
		return result, e
	}
	cert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	id, e := m.enrollLocked(Enrollment{Name: record.Name, IP: record.IP, CSR: req.CSR, Certificate: cert, Challenge: req.Token})
	if e != nil {
		return result, e
	}
	cfg, e := m.exportLocked(id)
	if e != nil {
		return result, e
	}
	if e = json.Unmarshal(cfg, &result.Config); e != nil {
		return result, e
	}
	ca, e := os.ReadFile(m.state.Config.Trust.CA)
	if e != nil {
		return result, e
	}
	result.CA = string(ca)
	result.Certificate = cert
	return result, nil
}
func (s *Issuance) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.TLS == nil || r.Host != s.Host || r.URL.Path != "/enroll" || r.URL.RawQuery != "" || r.Method != "POST" || r.Header.Get("Origin") != "" {
		JSON(w, 403, map[string]string{"error": "enrollment rejected"})
		return
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		JSON(w, 429, map[string]string{"error": "busy"})
		return
	}
	var req access.Request
	if Decode(w, r, &req) != nil {
		JSON(w, 400, map[string]string{"error": "enrollment rejected"})
		return
	}
	reply, e := s.Redeem(req)
	if e != nil {
		JSON(w, 409, map[string]string{"error": "enrollment rejected"})
		return
	}
	JSON(w, 200, reply)
}

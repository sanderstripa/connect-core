package management

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"github.com/sanderstripa/connect-core/internal/onboarding"
	"github.com/skip2/go-qrcode"
	"math/big"
	"os"
	"sync"
	"time"
)

type Invitation struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	IP          string    `json:"ip"`
	Status      string    `json:"status"`
	Expires     time.Time `json:"expires"`
	Fingerprint string    `json:"fingerprint,omitempty"`
	CSR         string    `json:"csr,omitempty"`
	Certificate string    `json:"certificate,omitempty"`
	DeviceID    string    `json:"device_id,omitempty"`
}
type InvitationState struct {
	Version int                   `json:"version"`
	Items   map[string]Invitation `json:"items"`
}
type Broker struct {
	mu        sync.Mutex
	manager   *Manager
	path, url string
	tlsDER    []byte
	ca        *x509.Certificate
	key       crypto.Signer
	state     InvitationState
}
type Registration struct {
	Token string `json:"token"`
	CSR   string `json:"csr"`
}

func NewBroker(m *Manager, path, origin, tlsPath, keyPath string) (*Broker, error) {
	certPEM, e := os.ReadFile(tlsPath)
	if e != nil {
		return nil, e
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("invalid enrollment TLS certificate")
	}
	if _, e = onboarding.Parse((onboarding.Link{URL: origin, Token: Random(), Certificate: block.Bytes}).String()); e != nil {
		return nil, e
	}
	caPEM, e := m.CA()
	if e != nil {
		return nil, e
	}
	caBlock, _ := pem.Decode(caPEM)
	if caBlock == nil {
		return nil, errors.New("invalid signing CA")
	}
	ca, e := x509.ParseCertificate(caBlock.Bytes)
	if e != nil || !ca.IsCA {
		return nil, errors.New("invalid signing CA")
	}
	priv, e := os.ReadFile(keyPath)
	if e != nil {
		return nil, e
	}
	kb, _ := pem.Decode(priv)
	if kb == nil {
		return nil, errors.New("invalid CA signing key")
	}
	k, e := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if e != nil {
		return nil, e
	}
	signer, ok := k.(crypto.Signer)
	if !ok {
		return nil, errors.New("invalid CA signing key")
	}
	public, e := x509.MarshalPKIXPublicKey(signer.Public())
	if e != nil || onboarding.Fingerprint(public) != onboarding.Fingerprint(ca.RawSubjectPublicKeyInfo) {
		return nil, errors.New("CA signing key mismatch")
	}
	b := &Broker{manager: m, path: path, url: origin, tlsDER: block.Bytes, ca: ca, key: signer, state: InvitationState{Version: 1, Items: map[string]Invitation{}}}
	if e = ReadJSON(path, &b.state); e != nil {
		if !os.IsNotExist(e) {
			return nil, e
		}
		if e = WriteJSON(path, b.state); e != nil {
			return nil, e
		}
	}
	if b.state.Version != 1 || b.state.Items == nil {
		return nil, errors.New("unsupported invitation state")
	}
	return b, nil
}
func (b *Broker) save(item Invitation) error {
	next := InvitationState{Version: 1, Items: map[string]Invitation{}}
	for k, v := range b.state.Items {
		next.Items[k] = v
	}
	next.Items[item.ID] = item
	if e := WriteJSON(b.path, next); e != nil {
		return e
	}
	b.state = next
	return nil
}
func (b *Broker) Create(name, ip string) (map[string]string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(name) < 1 || len(name) > 80 {
		return nil, errors.New("invalid name")
	}
	b.manager.mu.Lock()
	next := clone(b.manager.state)
	next.Config.Clients[Random()] = ip
	_, e := next.Config.Validate(true)
	b.manager.mu.Unlock()
	if e != nil {
		return nil, e
	}
	for _, v := range b.state.Items {
		if v.IP == ip && (v.Status == "invited" || v.Status == "pending" || v.Status == "issuing") && time.Now().Before(v.Expires) {
			return nil, errors.New("address already reserved")
		}
	}
	if len(b.state.Items) >= 128 {
		next := InvitationState{Version: 1, Items: map[string]Invitation{}}
		for id, v := range b.state.Items {
			if time.Now().Before(v.Expires) {
				next.Items[id] = v
			}
		}
		if e = WriteJSON(b.path, next); e != nil {
			return nil, e
		}
		b.state = next
		if len(b.state.Items) >= 128 {
			return nil, errors.New("too many pending invitations")
		}
	}
	token := Random()
	id := onboarding.Hash(token)
	s := Invitation{ID: id, Name: name, IP: ip, Status: "invited", Expires: time.Now().UTC().Add(15 * time.Minute)}
	link := (onboarding.Link{URL: b.url, Token: token, Certificate: b.tlsDER}).String()
	png, e := qrcode.Encode(link, qrcode.Medium, 384)
	if e != nil {
		return nil, e
	}
	if e = b.save(s); e != nil {
		return nil, e
	}
	return map[string]string{"id": id, "link": link, "qr_png": base64.StdEncoding.EncodeToString(png)}, nil
}
func (b *Broker) Register(r Registration) (Invitation, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	id := onboarding.Hash(r.Token)
	v, ok := b.state.Items[id]
	if !ok || len(r.Token) != 64 || v.Status == "cancelled" {
		return Invitation{}, errors.New("invitation unavailable")
	}
	if v.Status == "invited" && time.Now().After(v.Expires) {
		return Invitation{}, errors.New("invitation expired")
	}
	block, rest := pem.Decode([]byte(r.CSR))
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(rest) > 0 {
		return Invitation{}, errors.New("invalid CSR")
	}
	csr, e := x509.ParseCertificateRequest(block.Bytes)
	if e != nil || csr.CheckSignature() != nil || csr.Subject.CommonName != id {
		return Invitation{}, errors.New("invalid CSR proof")
	}
	if _, ok := csr.PublicKey.(ed25519.PublicKey); !ok {
		return Invitation{}, errors.New("client requires Ed25519")
	}
	if v.CSR != "" && v.CSR != r.CSR {
		return Invitation{}, errors.New("one-time invitation already bound to another key")
	}
	if v.Status == "invited" {
		v.CSR = r.CSR
		v.Fingerprint = onboarding.Fingerprint(csr.RawSubjectPublicKeyInfo)
		v.Status = "pending"
		if e = b.save(v); e != nil {
			return Invitation{}, e
		}
	}
	if time.Now().After(v.Expires) && v.Status != "approved" {
		return Invitation{}, errors.New("registration expired")
	}
	return v, nil
}
func (b *Broker) List() []Invitation {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := []Invitation{}
	for _, v := range b.state.Items {
		v.CSR = ""
		v.Certificate = ""
		out = append(out, v)
	}
	return out
}
func (b *Broker) Approve(id, fingerprint string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	v, ok := b.state.Items[id]
	if !ok || (v.Status != "pending" && v.Status != "issuing") || time.Now().After(v.Expires) || fingerprint != v.Fingerprint {
		return errors.New("matching independently verified key fingerprint required")
	}
	block, _ := pem.Decode([]byte(v.CSR))
	csr, e := x509.ParseCertificateRequest(block.Bytes)
	if e != nil {
		return e
	}
	if v.Certificate == "" {
		serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if e != nil {
			return e
		}
		now := time.Now()
		end := now.Add(30 * 24 * time.Hour)
		if b.ca.NotAfter.Before(end) {
			end = b.ca.NotAfter
		}
		if end.Before(now.Add(time.Hour)) {
			return errors.New("CA expires too soon")
		}
		leaf := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: v.Name}, NotBefore: now.Add(-time.Minute), NotAfter: end, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		raw, e := x509.CreateCertificate(rand.Reader, leaf, b.ca, csr.PublicKey, b.key)
		if e != nil {
			return e
		}
		v.Certificate = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}))
		v.Status = "issuing"
		if e = b.save(v); e != nil {
			return e
		}
	}
	deviceID, e := b.manager.Enroll(Enrollment{Name: v.Name, IP: v.IP, CSR: v.CSR, Certificate: v.Certificate, Challenge: id})
	if e != nil { // Recover a crash after the device committed but before ticket commit.
		block, _ := pem.Decode([]byte(v.Certificate))
		deviceID = onboarding.Fingerprint(block.Bytes)
		b.manager.mu.Lock()
		d, exists := b.manager.state.Devices[deviceID]
		same := exists && d.Access == "enabled" && d.Certificate == v.Certificate && d.IP == v.IP
		b.manager.mu.Unlock()
		if !same {
			return e
		}
	}
	v.DeviceID = deviceID
	v.Status = "approved"
	v.Expires = time.Now().UTC().Add(time.Hour)
	return b.save(v)
}
func (b *Broker) Cancel(id string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	v, ok := b.state.Items[id]
	if !ok {
		return errors.New("invitation not found")
	}
	if v.Status == "approved" || v.Status == "issuing" {
		return errors.New("revoke the issued device certificate instead")
	}
	v.Status = "cancelled"
	v.CSR = ""
	return b.save(v)
}
func (b *Broker) Result(r Registration) (map[string]any, error) {
	v, e := b.Register(r)
	if e != nil {
		return nil, e
	}
	if v.Status != "approved" {
		return map[string]any{"status": "pending", "fingerprint": v.Fingerprint}, nil
	}
	if time.Now().After(v.Expires) {
		return nil, errors.New("retrieval expired")
	}
	cfg, e := b.manager.Export(v.DeviceID)
	if e != nil {
		return nil, e
	}
	ca, e := b.manager.CA()
	if e != nil {
		return nil, e
	}
	return map[string]any{"status": "approved", "config": string(cfg), "certificate": v.Certificate, "ca": string(ca)}, nil
}

// A token is never placed in logs, state files, HTTP URLs or administration lists.

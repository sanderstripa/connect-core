package onboarding

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/sanderstripa/connect-core/internal/ipvpn"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

type Client struct {
	Link Link
	CSR  string
	Dir  string
	HTTP *http.Client
}

func NewClient(link, dir string) (*Client, error) {
	l, e := Parse(link)
	if e != nil {
		return nil, e
	}
	dir, e = filepath.Abs(dir)
	if e != nil {
		return nil, e
	}
	if e = os.Mkdir(dir, 0700); e != nil {
		return nil, errors.New("choose a new private client directory")
	}
	if e = protectDirectory(dir); e != nil {
		return nil, e
	}
	_, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return nil, e
	}
	raw, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return nil, e
	}
	if e = os.WriteFile(filepath.Join(dir, "device-key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw}), 0600); e != nil {
		return nil, e
	}
	csr, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: Hash(l.Token)}}, key)
	if e != nil {
		return nil, e
	}
	body := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}))
	if e = os.WriteFile(filepath.Join(dir, "proof.csr"), []byte(body), 0600); e != nil {
		return nil, e
	}
	return client(l, dir, body), nil
}
func ResumeClient(link, dir string) (*Client, error) {
	if e := protectDirectory(dir); e != nil {
		return nil, e
	}
	l, e := Parse(link)
	if e != nil {
		return nil, e
	}
	b, e := os.ReadFile(filepath.Join(dir, "proof.csr"))
	if e != nil {
		return nil, e
	}
	csrBlock, _ := pem.Decode(b)
	if csrBlock == nil {
		return nil, errors.New("invalid local proof")
	}
	csr, e := x509.ParseCertificateRequest(csrBlock.Bytes)
	if e != nil || csr.CheckSignature() != nil || csr.Subject.CommonName != Hash(l.Token) {
		return nil, errors.New("local proof belongs to another invitation")
	}
	pairKey, e := os.ReadFile(filepath.Join(dir, "device-key.pem"))
	if e != nil {
		return nil, e
	}
	kb, _ := pem.Decode(pairKey)
	if kb == nil {
		return nil, errors.New("invalid client key")
	}
	k, e := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if e != nil {
		return nil, e
	}
	key, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("Ed25519 key required")
	}
	pub, _ := x509.MarshalPKIXPublicKey(key.Public())
	if Fingerprint(pub) != Fingerprint(csr.RawSubjectPublicKeyInfo) {
		return nil, errors.New("local proof/key mismatch")
	}
	return client(l, dir, string(b)), nil
}
func client(l Link, dir, csr string) *Client {
	cert, _ := x509.ParseCertificate(l.Certificate)
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}, MaxIdleConnsPerHost: 1}
	return &Client{Link: l, Dir: dir, CSR: csr, HTTP: &http.Client{Timeout: 15 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("enrollment redirects forbidden") }}}
}
func (c *Client) Fingerprint() string {
	b, _ := pem.Decode([]byte(c.CSR))
	csr, _ := x509.ParseCertificateRequest(b.Bytes)
	return Fingerprint(csr.RawSubjectPublicKeyInfo)
}
func (c *Client) Poll(ctx context.Context) (bool, error) {
	body, _ := json.Marshal(map[string]string{"token": c.Link.Token, "csr": c.CSR})
	r, e := http.NewRequestWithContext(ctx, "POST", c.Link.URL+"/result", bytes.NewReader(body))
	if e != nil {
		return false, e
	}
	r.Header.Set("Content-Type", "application/json")
	resp, e := c.HTTP.Do(r)
	if e != nil {
		return false, errors.New("secure enrollment connection failed")
	}
	defer resp.Body.Close()
	b, e := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if e != nil || len(b) > 65536 {
		return false, errors.New("invalid enrollment response")
	}
	var v struct {
		Status      string `json:"status"`
		Config      string `json:"config"`
		Certificate string `json:"certificate"`
		CA          string `json:"ca"`
		Error       string `json:"error"`
		Fingerprint string `json:"fingerprint"`
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e = d.Decode(&v); e != nil {
		return false, errors.New("invalid enrollment response")
	}
	if resp.StatusCode != 200 {
		return false, fmt.Errorf("enrollment rejected: %s", v.Error)
	}
	if v.Status == "pending" {
		return false, nil
	}
	if v.Status != "approved" {
		return false, errors.New("unsupported enrollment state")
	}
	var cfg ipvpn.Config
	d = json.NewDecoder(bytes.NewReader([]byte(v.Config)))
	d.DisallowUnknownFields()
	if e = d.Decode(&cfg); e != nil {
		return false, e
	}
	if _, e = cfg.Validate(false); e != nil {
		return false, e
	}
	if cfg.Trust.CA != "ca.pem" || cfg.Trust.Cert != "device.pem" || cfg.Trust.Key != "device-key.pem" {
		return false, errors.New("unsafe credential export paths")
	}
	certBlock, _ := pem.Decode([]byte(v.Certificate))
	if certBlock == nil {
		return false, errors.New("invalid issued certificate")
	}
	cert, e := x509.ParseCertificate(certBlock.Bytes)
	if e != nil || Fingerprint(cert.RawSubjectPublicKeyInfo) != c.Fingerprint() {
		return false, errors.New("issued certificate belongs to another key")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(v.CA)) {
		return false, errors.New("invalid CA")
	}
	if _, e = cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); e != nil {
		return false, e
	}
	for name, value := range map[string]string{"ca.pem": v.CA, "device.pem": v.Certificate, "connect-ip-client.json": v.Config} {
		if e = os.WriteFile(filepath.Join(c.Dir, name), []byte(value), 0600); e != nil {
			return false, e
		}
	}
	return true, nil
}

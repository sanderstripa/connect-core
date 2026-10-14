// Package access defines one-use CONNECT enrollment invitations, never VPN keys.
package access

import (
	"bytes"
	"context"
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
	"github.com/sanderstripa/connect-core/internal/ipvpn"
	"github.com/sanderstripa/connect-core/internal/onboarding"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

const MaxLink = 4096

type Invitation struct {
	URL   string
	Pin   string
	Token string
	Panel *onboarding.Link
}
type Request struct {
	Token string `json:"token"`
	CSR   string `json:"csr"`
}
type Response struct {
	Config      ipvpn.Config `json:"config"`
	CA          string       `json:"ca"`
	Certificate string       `json:"certificate"`
}

func hex32(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && s == hex.EncodeToString(b)
}
func Parse(s string) (Invitation, error) {
	var i Invitation
	if len(s) > MaxLink {
		return i, errors.New("invitation too long")
	}
	u, e := url.Parse(s)
	if e != nil || u.Scheme != "connect" || u.Host != "enroll" || u.Path != "" || u.User != nil || u.Opaque != "" {
		return i, errors.New("invalid CONNECT invitation")
	}
	q, e := url.ParseQuery(u.RawQuery)
	if e == nil && len(q) == 4 {
		l, err := onboarding.Parse(s)
		if err != nil {
			return i, err
		}
		cert, err := x509.ParseCertificate(l.Certificate)
		if err != nil {
			return i, err
		}
		return Invitation{URL: l.URL + "/result", Pin: SPKI(cert), Token: l.Token, Panel: &l}, nil
	}
	if e != nil || len(q) != 3 || len(q["v"]) != 1 || len(q["url"]) != 1 || len(q["pin"]) != 1 || q.Get("v") != "1" || !hex32(q.Get("pin")) || !hex32(u.Fragment) {
		return i, errors.New("invalid invitation fields")
	}
	ep, e := url.Parse(q.Get("url"))
	if e != nil || ep.Scheme != "https" || ep.Host == "" || ep.User != nil || ep.Path != "/enroll" || ep.RawQuery != "" || ep.Fragment != "" || ep.RawPath != "" {
		return i, errors.New("enrollment requires an exact HTTPS endpoint")
	}
	return Invitation{URL: ep.String(), Pin: q.Get("pin"), Token: u.Fragment}, nil
}
func Link(i Invitation) (string, error) {
	if i.Panel != nil {
		cert, err := x509.ParseCertificate(i.Panel.Certificate)
		if err != nil || i.URL != i.Panel.URL+"/result" || i.Token != i.Panel.Token || i.Pin != SPKI(cert) {
			return "", errors.New("inconsistent panel invitation")
		}
		s := i.Panel.String()
		_, err = onboarding.Parse(s)
		return s, err
	}
	q := url.Values{"v": {"1"}, "url": {i.URL}, "pin": {i.Pin}}
	s := "connect://enroll?" + q.Encode() + "#" + i.Token
	_, e := Parse(s)
	return s, e
}
func KeyAndCSR(token string) ([]byte, string, error) {
	if !hex32(token) {
		return nil, "", errors.New("invalid token")
	}
	_, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return nil, "", e
	}
	raw, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return nil, "", e
	}
	csr, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: token}}, key)
	if e != nil {
		return nil, "", e
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw}), string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})), nil
}
func SPKI(cert *x509.Certificate) string {
	h := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(h[:])
}
func Redeem(ctx context.Context, i Invitation, csr string) (Response, error) {
	var reply Response
	if _, err := Link(i); err != nil {
		return reply, err
	}
	if len(csr) > 8192 {
		return reply, errors.New("enrollment CSR too large")
	}
	if i.Panel != nil {
		return redeemPanel(ctx, *i.Panel, csr)
	}
	ep, _ := url.Parse(i.URL)
	// Invitation SPKI is an explicit out-of-band trust anchor, including lab CAs.
	// Standard chain verification is replaced ONLY by pin + SAN + validity checks.
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: ep.Hostname(), InsecureSkipVerify: true, VerifyConnection: func(s tls.ConnectionState) error {
		if len(s.PeerCertificates) == 0 {
			return errors.New("missing enrollment identity")
		}
		c := s.PeerCertificates[0]
		now := time.Now()
		if SPKI(c) != i.Pin || now.Before(c.NotBefore) || now.After(c.NotAfter) || c.IsCA || c.VerifyHostname(ep.Hostname()) != nil {
			return errors.New("enrollment identity rejected")
		}
		for _, u := range c.ExtKeyUsage {
			if u == x509.ExtKeyUsageServerAuth {
				return nil
			}
		}
		return errors.New("server EKU required")
	}}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: tlsConfig, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	body, _ := json.Marshal(Request{Token: i.Token, CSR: csr})
	req, e := http.NewRequestWithContext(ctx, "POST", i.URL, bytes.NewReader(body))
	if e != nil {
		return reply, e
	}
	req.Header.Set("Content-Type", "application/json")
	resp, e := client.Do(req)
	if e != nil {
		return reply, errors.New("secure enrollment connection failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return reply, errors.New("invitation expired, consumed or registration rejected")
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, 65537))
	dec.DisallowUnknownFields()
	if e = dec.Decode(&reply); e != nil {
		return reply, errors.New("invalid enrollment response")
	}
	if dec.Decode(new(any)) != io.EOF {
		return reply, errors.New("trailing enrollment response")
	}
	if _, e = reply.Config.Validate(false); e != nil {
		return reply, e
	}
	return reply, nil
}

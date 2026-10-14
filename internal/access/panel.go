package access

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/sanderstripa/connect-core/internal/onboarding"
)

var ErrPending = errors.New("device approval pending")

// The current panel binds a token to one CSR and requires explicit approval of
// the independently compared public-key fingerprint. No private file is written.
func redeemPanel(ctx context.Context, link onboarding.Link, csr string) (Response, error) {
	var reply Response
	block, rest := pem.Decode([]byte(csr))
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(bytes.TrimSpace(rest)) != 0 {
		return reply, errors.New("invalid device proof")
	}
	proof, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || proof.CheckSignature() != nil || proof.Subject.CommonName != onboarding.Hash(link.Token) {
		return reply, errors.New("device proof does not match invitation")
	}
	cert, err := x509.ParseCertificate(link.Certificate)
	if err != nil {
		return reply, errors.New("invalid enrollment identity")
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	body, _ := json.Marshal(Request{Token: link.Token, CSR: csr})
	r, err := http.NewRequestWithContext(ctx, "POST", link.URL+"/result", bytes.NewReader(body))
	if err != nil {
		return reply, err
	}
	r.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(r)
	if err != nil {
		return reply, errors.New("secure panel registration failed")
	}
	defer resp.Body.Close()
	var result struct{ Status, Config, Certificate, CA, Error, Fingerprint string }
	d := json.NewDecoder(io.LimitReader(resp.Body, 65537))
	d.DisallowUnknownFields()
	if err = d.Decode(&result); err != nil || d.Decode(new(any)) != io.EOF || resp.StatusCode != http.StatusOK {
		return reply, errors.New("panel rejected registration")
	}
	if result.Status == "pending" {
		if result.Fingerprint != onboarding.Fingerprint(proof.RawSubjectPublicKeyInfo) {
			return reply, errors.New("panel proof mismatch")
		}
		return reply, ErrPending
	}
	if result.Status != "approved" {
		return reply, errors.New("unsupported panel registration state")
	}
	d = json.NewDecoder(bytes.NewReader([]byte(result.Config)))
	d.DisallowUnknownFields()
	if err = d.Decode(&reply.Config); err != nil || d.Decode(new(any)) != io.EOF {
		return reply, errors.New("invalid issued configuration")
	}
	if _, err = reply.Config.Validate(false); err != nil {
		return reply, err
	}
	reply.CA, reply.Certificate = result.CA, result.Certificate
	return reply, nil
}

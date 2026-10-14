// Package onboarding defines the versioned connect:// client import format.
package onboarding

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/url"
	"strings"
)

const Version = 1

type Link struct {
	URL, Token  string
	Certificate []byte
}

func (l Link) String() string {
	q := url.Values{"v": {"1"}, "u": {l.URL}, "t": {l.Token}, "c": {base64.RawURLEncoding.EncodeToString(l.Certificate)}}
	return "connect://enroll?" + q.Encode()
}
func Parse(s string) (Link, error) {
	var l Link
	if len(s) > 4096 {
		return l, errors.New("link too long")
	}
	u, e := url.Parse(s)
	if e != nil || u.Scheme != "connect" || u.Host != "enroll" || u.Path != "" || u.User != nil || u.Fragment != "" {
		return l, errors.New("unsupported connect link")
	}
	q, e := url.ParseQuery(u.RawQuery)
	if e != nil || len(q) != 4 || q.Get("v") != "1" {
		return l, errors.New("unsupported import version")
	}
	for _, v := range q {
		if len(v) != 1 {
			return l, errors.New("duplicate link field")
		}
	}
	l.URL = q.Get("u")
	l.Token = q.Get("t")
	token, e := hex.DecodeString(l.Token)
	if e != nil || len(token) != 32 {
		return l, errors.New("invalid invite token")
	}
	ep, e := url.Parse(l.URL)
	if e != nil || ep.Scheme != "https" || ep.Hostname() == "" || ep.User != nil || ep.Path != "" || ep.RawQuery != "" || ep.Fragment != "" || strings.ContainsAny(ep.Host, "\r\n") {
		return l, errors.New("HTTPS enrollment origin required")
	}
	l.Certificate, e = base64.RawURLEncoding.DecodeString(q.Get("c"))
	if e != nil {
		return l, e
	}
	cert, e := x509.ParseCertificate(l.Certificate)
	if e != nil || cert.VerifyHostname(ep.Hostname()) != nil {
		return l, errors.New("TLS certificate does not match enrollment origin")
	}
	return l, nil
}
func Hash(s string) string { sum := sha256.Sum256([]byte(s)); return hex.EncodeToString(sum[:]) }
func Fingerprint(publicKey []byte) string {
	sum := sha256.Sum256(publicKey)
	return hex.EncodeToString(sum[:])
}

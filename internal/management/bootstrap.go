package management

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"github.com/sanderstripa/connect-core/internal/core"
	"github.com/sanderstripa/connect-core/internal/ipvpn"
	"math/big"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

// Bootstrap creates only server/CA credentials, never any client private key.
func Bootstrap(dir, endpoint, enrollmentURL string) (State, error) {
	s := State{Version: 1, Devices: map[string]Device{}}
	ap, e := netip.ParseAddrPort(endpoint)
	if e != nil {
		return s, e
	}
	u, e := url.Parse(enrollmentURL)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return s, errors.New("HTTPS enrollment origin required")
	}
	if e = os.Mkdir(dir, 0700); e != nil {
		return s, e
	}
	now := time.Now()
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return s, e
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CONNECT managed CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(5, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, e := x509.CreateCertificate(rand.Reader, root, root, pub, key)
	if e != nil {
		return s, e
	}
	root, e = x509.ParseCertificate(der)
	if e != nil {
		return s, e
	}
	write := func(name, typ string, b []byte) error {
		return os.WriteFile(filepath.Join(dir, name), pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: b}), 0600)
	}
	if e = write("ca.pem", "CERTIFICATE", der); e != nil {
		return s, e
	}
	pk, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return s, e
	}
	if e = write("ca-key.pem", "PRIVATE KEY", pk); e != nil {
		return s, e
	}
	leaf := func(name, host string, serial int64) error {
		p, k, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			return e
		}
		cert := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "CONNECT " + name}, NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		if ip := net.ParseIP(host); ip != nil {
			cert.IPAddresses = []net.IP{ip}
		} else {
			cert.DNSNames = []string{host}
		}
		raw, e := x509.CreateCertificate(rand.Reader, cert, root, p, key)
		if e != nil {
			return e
		}
		if e = write(name+".pem", "CERTIFICATE", raw); e != nil {
			return e
		}
		priv, e := x509.MarshalPKCS8PrivateKey(k)
		if e != nil {
			return e
		}
		return write(name+"-key.pem", "PRIVATE KEY", priv)
	}
	if e = leaf("server", ap.Addr().String(), 2); e != nil {
		return s, e
	}
	if e = leaf("enrollment", u.Hostname(), 3); e != nil {
		return s, e
	}
	s.Config = ipvpn.Config{Version: 2, Environment: "managed-vps", Endpoint: endpoint, Interface: "cc-vps0", DeviceNetwork: "10.231.0.0/24", Clients: map[string]string{}, Destinations: []string{"0.0.0.0/0"}, Trust: core.Config{Version: 1, CA: filepath.Join(dir, "ca.pem"), Cert: filepath.Join(dir, "server.pem"), Key: filepath.Join(dir, "server-key.pem")}}
	if _, e = s.Config.Validate(true); e != nil {
		return s, e
	}
	return s, nil
}

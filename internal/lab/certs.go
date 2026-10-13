// Package lab generates disposable certificates exclusively for the local lab.
package lab

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/sanderstripa/connect-core/internal/core"
)

func Generate(dir string) (core.Config, core.Config, error) {
	var server, client core.Config
	if err := os.MkdirAll(dir, 0700); err != nil {
		return server, client, err
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return server, client, err
	}
	now := time.Now()
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CONNECT disposable lab CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, root, root, pub, key)
	if err != nil {
		return server, client, err
	}
	caPath := filepath.Join(dir, "ca.pem")
	if err = os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		return server, client, err
	}
	root, err = x509.ParseCertificate(der)
	if err != nil {
		return server, client, err
	}
	makeLeaf := func(name string, serial int64, usage x509.ExtKeyUsage) (string, string, []byte, error) {
		p, k, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			return "", "", nil, e
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		if usage == x509.ExtKeyUsageServerAuth {
			leaf.DNSNames = []string{"localhost"}
			leaf.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		}
		raw, e := x509.CreateCertificate(rand.Reader, leaf, root, p, key)
		if e != nil {
			return "", "", nil, e
		}
		pk, e := x509.MarshalPKCS8PrivateKey(k)
		if e != nil {
			return "", "", nil, e
		}
		cp, kp := filepath.Join(dir, name+".pem"), filepath.Join(dir, name+".key")
		if e = os.WriteFile(cp, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}), 0600); e != nil {
			return "", "", nil, e
		}
		e = os.WriteFile(kp, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}), 0600)
		return cp, kp, raw, e
	}
	sc, sk, _, err := makeLeaf("server", 2, x509.ExtKeyUsageServerAuth)
	if err != nil {
		return server, client, err
	}
	cc, ck, raw, err := makeLeaf("client", 3, x509.ExtKeyUsageClientAuth)
	if err != nil {
		return server, client, err
	}
	server = core.Config{Version: 1, Listen: "127.0.0.1:17443", CA: caPath, Cert: sc, Key: sk, AllowedClients: []string{core.Fingerprint(raw)}, Services: map[string]string{"http": "127.0.0.1:18080"}}
	client = core.Config{Version: 1, Listen: "127.0.0.1:18081", Server: server.Listen, ServerName: "localhost", Service: "http", CA: caPath, Cert: cc, Key: ck}
	return server, client, nil
}

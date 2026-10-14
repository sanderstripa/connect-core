// connect-cert obtains IP certificates using the maintained lego ACME client.
// The installer opens only the panel's own port, never another service's port.
package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/go-acme/lego/v5/certificate"
	"github.com/go-acme/lego/v5/challenge/http01"
	"github.com/go-acme/lego/v5/challenge/tlsalpn01"
	"github.com/go-acme/lego/v5/lego"
	"github.com/go-acme/lego/v5/registration"
)

type account struct {
	key      crypto.Signer
	resource *acme.ExtendedAccount
}

func (a *account) GetEmail() string                       { return "" }
func (a *account) GetPrivateKey() crypto.Signer           { return a.key }
func (a *account) GetRegistration() *acme.ExtendedAccount { return a.resource }

func atomic(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".connect-cert-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

func run(args []string) error {
	if len(args) != 5 {
		return errors.New("usage: connect-cert IP ACCOUNT_DIR OUTPUT_DIR PANEL_PORT ACME_DIRECTORY")
	}
	ip := net.ParseIP(args[0])
	if ip == nil || ip.To4() == nil || ip.IsUnspecified() || ip.IsMulticast() {
		return errors.New("numeric IPv4 required")
	}
	port := args[3]
	if port != "443" && port != "80" {
		return errors.New("IP ACME validation requires the owned panel port 443 or 80")
	}
	for _, dir := range args[1:3] {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}
	a := &account{}
	keyPath := filepath.Join(args[1], "account-key.pem")
	data, err := os.ReadFile(keyPath)
	if errors.Is(err, os.ErrNotExist) {
		key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			return e
		}
		der, e := x509.MarshalPKCS8PrivateKey(key)
		if e != nil {
			return e
		}
		data = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		if e = atomic(keyPath, data); e != nil {
			return e
		}
	} else if err != nil {
		return err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return errors.New("invalid ACME account key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	var ok bool
	a.key, ok = parsed.(crypto.Signer)
	if !ok {
		return errors.New("invalid signing key")
	}
	resourcePath := filepath.Join(args[1], "account.json")
	if data, err = os.ReadFile(resourcePath); err == nil {
		if err = json.Unmarshal(data, &a.resource); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	config := lego.NewConfig(a)
	config.CADirURL = args[4]
	config.UserAgent = "CONNECT-Core-IP-panel"
	config.Certificate.Timeout = 90 * time.Second
	client, err := lego.NewClient(config)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	if a.resource == nil {
		a.resource, err = client.Registration.Register(ctx, registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return err
		}
		data, err = json.Marshal(a.resource)
		if err != nil {
			return err
		}
		if err = atomic(resourcePath, data); err != nil {
			return err
		}
	}
	if port == "443" {
		err = client.Challenge.SetTLSALPN01Provider(tlsalpn01.NewProviderServer(ip.String(), port))
	} else {
		err = client.Challenge.SetHTTP01Provider(http01.NewProviderServer(ip.String(), port))
	}
	if err != nil {
		return err
	}
	cert, err := client.Certificate.Obtain(ctx, certificate.ObtainRequest{Domains: []string{ip.String()}, KeyType: certcrypto.EC256, Bundle: true, Profile: "shortlived", AlwaysDeactivateAuthorizations: true})
	if err != nil {
		return err
	}
	pair, err := tls.X509KeyPair(cert.Certificate, cert.PrivateKey)
	if err != nil {
		return err
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return err
	}
	if err = leaf.VerifyHostname(ip.String()); err != nil {
		return err
	}
	if time.Until(leaf.NotAfter) < 24*time.Hour {
		return errors.New("certificate lifetime too short")
	}
	// OUTPUT_DIR is a staging directory. Python atomically publishes a directory
	// symlink only after it verifies the chain, so renewal cannot mix key pairs.
	if err = atomic(filepath.Join(args[2], "cert.pem"), cert.Certificate); err != nil {
		return err
	}
	if err = atomic(filepath.Join(args[2], "key.pem"), cert.PrivateKey); err != nil {
		return err
	}
	fmt.Println("IP certificate obtained; public ACME challenge validated")
	return nil
}
func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "IP certificate failed:", err)
		os.Exit(1)
	}
}

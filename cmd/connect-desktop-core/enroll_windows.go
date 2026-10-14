//go:build windows

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/sanderstripa/connect-core/internal/access"
	"github.com/sanderstripa/connect-core/internal/desktop"
	"github.com/sanderstripa/connect-core/internal/onboarding"
	"os"
	"time"
)

type pendingIdentity struct {
	Version  int
	LinkHash string
	Key      []byte
	CSR      string
}

func enrollmentIdentity(path, link string, invitation access.Invitation) (pendingIdentity, error) {
	challenge := invitation.Token
	if invitation.Panel != nil {
		challenge = onboarding.Hash(challenge)
	}
	hash := onboarding.Hash(link)
	if sealed, err := os.ReadFile(path); err == nil && len(sealed) < 65536 {
		if raw, err := protect(sealed, true); err == nil {
			defer clear(raw)
			var p pendingIdentity
			if json.Unmarshal(raw, &p) == nil && p.Version == 1 && p.LinkHash == hash {
				block, _ := pem.Decode([]byte(p.CSR))
				if block != nil {
					csr, err := x509.ParseCertificateRequest(block.Bytes)
					// A resumed registration must keep the same signed proof and key.
					if err == nil && csr.CheckSignature() == nil && csr.Subject.CommonName == challenge {
						kb, _ := pem.Decode(p.Key)
						if kb != nil {
							key, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
							if err == nil {
								if signer, ok := key.(ed25519.PrivateKey); ok {
									pub, err := x509.MarshalPKIXPublicKey(signer.Public())
									if err == nil && onboarding.Fingerprint(pub) == onboarding.Fingerprint(csr.RawSubjectPublicKeyInfo) {
										return p, nil
									}
								}
							}
						}
					}
				}
				return p, errors.New("invalid pending identity")
			}
		}
	}
	key, csr, err := access.KeyAndCSR(challenge)
	if err != nil {
		return pendingIdentity{}, err
	}
	p := pendingIdentity{Version: 1, LinkHash: hash, Key: key, CSR: csr}
	raw, err := json.Marshal(p)
	if err != nil {
		return p, err
	}
	defer clear(raw)
	sealed, err := protect(raw, false)
	if err == nil {
		err = os.WriteFile(path, sealed, 0600)
	}
	return p, err
}

func (w *worker) enroll(path, link string) {
	invitation, e := access.Parse(link)
	if e != nil {
		w.mu.Lock()
		w.code = 4
		w.mu.Unlock()
		return
	}
	w.stop()
	w.mu.Lock()
	if w.code == 5 {
		w.mu.Unlock()
		return
	}
	w.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	w.mu.Lock()
	w.cancel = cancel
	w.done = make(chan struct{})
	done := w.done
	w.state = desktop.Enrolling
	w.fingerprint = ""
	w.code = 0
	w.mu.Unlock()
	go func() {
		defer close(done)
		pending := path + ".pending"
		identity, e := enrollmentIdentity(pending, link, invitation)
		key, csr := identity.Key, identity.CSR
		if e == nil {
			block, _ := pem.Decode([]byte(csr))
			proof, err := x509.ParseCertificateRequest(block.Bytes)
			if err != nil {
				e = err
			} else {
				w.mu.Lock()
				w.fingerprint = onboarding.Fingerprint(proof.RawSubjectPublicKeyInfo)
				w.mu.Unlock()
				w.emit()
			}
		}
		var b bundle
		if e == nil {
			var reply access.Response
			for {
				reply, e = access.Redeem(ctx, invitation, csr)
				if !errors.Is(e, access.ErrPending) {
					break
				}
				select {
				case <-ctx.Done():
					e = ctx.Err()
				case <-time.After(3 * time.Second):
				}
				if ctx.Err() != nil {
					break
				}
			}
			if e == nil {
				b = bundle{Config: reply.Config, CA: []byte(reply.CA), Cert: []byte(reply.Certificate), Key: key}
				automaticVPN(&b.Config)
				_, e = b.Config.Validate(false)
				if e == nil {
					_, e = b.tls()
				}
			}
		}
		if e == nil {
			e = save(path, b)
		}
		w.mu.Lock()
		if e == nil {
			w.b = b
			w.state = desktop.Ready
			w.code = 0
			w.stats = nil
			w.since = time.Time{}
			w.elapsed = 0
			w.dnsRTT = 0
			_ = os.Remove(pending)
		} else if errors.Is(ctx.Err(), context.Canceled) {
			w.state = desktop.Ready
			if w.b.Config.Version != 2 {
				w.state = desktop.Idle
			}
			w.code = 0
		} else {
			w.state = desktop.Failed
			w.code = 4
		}
		w.mu.Unlock()
		w.emit()
	}()
}

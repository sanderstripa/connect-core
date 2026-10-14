// connect-control owns only the CONNECT IP server it starts. It never invokes
// system service commands, shells, routes, DNS or firewall configuration.
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/sanderstripa/connect-core/internal/core"
	"github.com/sanderstripa/connect-core/internal/ipvpn"
	"github.com/sanderstripa/connect-core/internal/management"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"
)

type config struct {
	Listen            string `json:"listen"`
	TokenFile         string `json:"token_file"`
	StateFile         string `json:"state_file"`
	EnrollmentListen  string `json:"enrollment_listen,omitempty"`
	EnrollmentURL     string `json:"enrollment_url,omitempty"`
	EnrollmentTLSCert string `json:"enrollment_tls_cert,omitempty"`
	EnrollmentTLSKey  string `json:"enrollment_tls_key,omitempty"`
	IssuerKey         string `json:"issuer_key,omitempty"`
}

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) == 4 && os.Args[1] == "init" {
		c, e := ipvpn.Load(os.Args[3])
		if e != nil {
			return e
		}
		if _, e = c.Validate(true); e != nil {
			return e
		}
		// Canonicalize credential paths before the state changes directories.
		for _, p := range []*string{&c.Trust.CA, &c.Trust.Cert, &c.Trust.Key} {
			*p, e = filepath.Abs(*p)
			if e != nil {
				return e
			}
		}
		dir, e := filepath.Abs(os.Args[2])
		if e != nil {
			return e
		}
		if e = os.Mkdir(dir, 0700); e != nil {
			return e
		}
		token := filepath.Join(dir, "control-token")
		state := filepath.Join(dir, "state.json")
		if e = os.WriteFile(token, []byte(management.Random()), 0600); e != nil {
			return e
		}
		s := management.State{Version: 1, Config: c, Devices: map[string]management.Device{}}
		for pin, ip := range c.Clients {
			s.Devices[pin] = management.Device{ID: pin, Name: "Device " + ip, IP: ip, Access: "enabled"}
		}
		if e = management.WriteJSON(state, s); e != nil {
			return e
		}
		return management.WriteJSON(filepath.Join(dir, "control.json"), config{Listen: "127.0.0.1:17891", TokenFile: token, StateFile: state})
	}
	if len(os.Args) != 3 || os.Args[1] != "serve" {
		return fmt.Errorf("usage: connect-control init NEW_DIR ip-server.json | serve control.json")
	}
	var cfg config
	if e := management.ReadJSON(os.Args[2], &cfg); e != nil {
		return e
	}
	if e := core.Loopback(cfg.Listen); e != nil {
		return e
	}
	b, e := os.ReadFile(cfg.TokenFile)
	if e != nil {
		return e
	}
	token := strings.TrimSpace(string(b))
	if len(token) != 64 {
		return fmt.Errorf("invalid control token")
	}
	m, e := management.New(cfg.StateFile)
	if e != nil {
		return e
	}
	defer m.Stop()
	l, e := net.Listen("tcp", cfg.Listen)
	if e != nil {
		return e
	}
	defer l.Close()
	api := &management.API{Manager: m, Token: token, Host: l.Addr().String()}
	if cfg.IssuerKey != "" {
		issuance, err := management.NewIssuance(m, cfg.IssuerKey, cfg.EnrollmentURL, cfg.EnrollmentTLSCert, cfg.EnrollmentTLSKey)
		if err != nil {
			return err
		}
		el, err := net.Listen("tcp", cfg.EnrollmentListen)
		if err != nil {
			return err
		}
		defer el.Close()
		enrollmentServer := &http.Server{Handler: issuance, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 8192, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13}}
		api.Issuance = issuance
		defer enrollmentServer.Close()
		go func() { _ = enrollmentServer.ServeTLS(el, cfg.EnrollmentTLSCert, cfg.EnrollmentTLSKey) }()
	}
	srv := &http.Server{Handler: api, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	go func() {
		<-ctx.Done()
		c, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		srv.Shutdown(c)
	}()
	fmt.Println("CONNECT local control ready; data server is stopped")
	e = srv.Serve(l)
	if e == http.ErrServerClosed {
		return nil
	}
	return e
}

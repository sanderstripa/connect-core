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
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type config struct {
	Listen           string `json:"listen"`
	TokenFile        string `json:"token_file"`
	StateFile        string `json:"state_file"`
	OwnedTUN         bool   `json:"owned_tun,omitempty"`
	AutoStart        bool   `json:"auto_start,omitempty"`
	SigningKey       string `json:"signing_key,omitempty"`
	InvitationsFile  string `json:"invitations_file,omitempty"`
	EnrollmentURL    string `json:"enrollment_url,omitempty"`
	EnrollmentListen string `json:"enrollment_listen,omitempty"`
	EnrollmentCert   string `json:"enrollment_cert,omitempty"`
	EnrollmentKey    string `json:"enrollment_key,omitempty"`
}

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) == 2 && os.Args[1] == "version" {
		fmt.Println(management.Version)
		return nil
	}
	if len(os.Args) == 5 && os.Args[1] == "init-vps" {
		dir, e := filepath.Abs(os.Args[2])
		if e != nil {
			return e
		}
		if e = os.Mkdir(dir, 0700); e != nil {
			return e
		}
		creds := filepath.Join(dir, "credentials")
		s, e := management.Bootstrap(creds, os.Args[3], os.Args[4])
		if e != nil {
			return e
		}
		token := filepath.Join(dir, "control-token")
		state := filepath.Join(dir, "state.json")
		if e = os.WriteFile(token, []byte(management.Random()), 0600); e != nil {
			return e
		}
		if e = management.WriteJSON(state, s); e != nil {
			return e
		}
		return management.WriteJSON(filepath.Join(dir, "control.json"), config{Listen: "127.0.0.1:17891", TokenFile: token, StateFile: state, SigningKey: filepath.Join(creds, "ca-key.pem"), InvitationsFile: filepath.Join(dir, "invitations.json"), EnrollmentURL: os.Args[4], EnrollmentListen: "127.0.0.1:17900", EnrollmentCert: filepath.Join(creds, "enrollment.pem"), EnrollmentKey: filepath.Join(creds, "enrollment-key.pem")})
	}
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
	if len(os.Args) != 3 || (os.Args[1] != "serve" && os.Args[1] != "check") {
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
	if cfg.OwnedTUN {
		if e = m.UseOwnedTUN(); e != nil {
			return e
		}
	}
	var broker *management.Broker
	var enroll *http.Server
	var el net.Listener
	if cfg.EnrollmentListen != "" {
		if os.Args[1] == "check" {
			if _, e = os.Stat(cfg.InvitationsFile); e != nil {
				return e
			}
		}
		broker, e = management.NewBroker(m, cfg.InvitationsFile, cfg.EnrollmentURL, cfg.EnrollmentCert, cfg.SigningKey)
		if e != nil {
			return e
		}
		pair, e := tls.LoadX509KeyPair(cfg.EnrollmentCert, cfg.EnrollmentKey)
		if e != nil {
			return e
		}
		if os.Args[1] == "check" {
			if e = m.CheckTLS(); e != nil {
				return e
			}
			fmt.Println("api_version=1 state_version=1 invitations_version=1")
			return nil
		}
		origin, e := url.Parse(cfg.EnrollmentURL)
		if e != nil {
			return e
		}
		el, e = net.Listen("tcp", cfg.EnrollmentListen)
		if e != nil {
			return e
		}
		defer el.Close()
		enroll = &http.Server{Handler: &management.RegistrationAPI{Broker: broker, Host: origin.Host}, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}}, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 20 * time.Second, MaxHeaderBytes: 8192}
	}
	if os.Args[1] == "check" {
		fmt.Println("api_version=1 state_version=1")
		return nil
	}
	l, e := net.Listen("tcp", cfg.Listen)
	if e != nil {
		return e
	}
	defer l.Close()
	api := &management.API{Manager: m, Broker: broker, Token: token, Host: l.Addr().String()}
	srv := &http.Server{Handler: api, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	go func() {
		<-ctx.Done()
		c, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		srv.Shutdown(c)
		if enroll != nil {
			enroll.Shutdown(c)
		}
	}()
	if cfg.AutoStart {
		if e = m.Start(); e != nil {
			return e
		}
	}
	fmt.Println("CONNECT local control ready")
	if enroll != nil {
		go func() {
			if e := enroll.ServeTLS(el, "", ""); e != nil && e != http.ErrServerClosed {
				cancel()
			}
		}()
	}
	e = srv.Serve(l)
	if e == http.ErrServerClosed {
		return nil
	}
	return e
}

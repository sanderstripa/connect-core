package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"github.com/sanderstripa/connect-core/internal/management"
	"github.com/sanderstripa/connect-core/internal/panel"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func readPassword() (string, error) {
	fmt.Fprintln(os.Stderr, "Enter a password (12+ bytes) via stdin; use a private terminal/input source.")
	r := bufio.NewReader(os.Stdin)
	b, e := r.ReadString('\n')
	if e != nil && len(b) == 0 {
		return "", e
	}
	b = strings.TrimRight(b, "\r\n")
	if len(b) < 12 || len(b) > 1024 {
		return "", fmt.Errorf("password must contain 12..1024 bytes")
	}
	return b, nil
}
func run() error {
	if len(os.Args) == 5 && os.Args[1] == "init" {
		dir, e := filepath.Abs(os.Args[2])
		if e != nil {
			return e
		}
		token, e := filepath.Abs(os.Args[4])
		if e != nil {
			return e
		}
		password, e := readPassword()
		if e != nil {
			return e
		}
		salt := management.Random()
		hash, e := panel.Password(password, salt)
		if e != nil {
			return e
		}
		c := panel.Config{Listen: "127.0.0.1:17890", CoreURL: os.Args[3], TokenFile: token, Username: "admin", Salt: salt, PasswordHash: hash}
		if _, e = panel.New(c); e != nil {
			return e
		}
		if e = os.Mkdir(dir, 0700); e != nil {
			return e
		}
		return management.WriteJSON(filepath.Join(dir, "ui.json"), c)
	}
	if len(os.Args) != 3 {
		return fmt.Errorf("usage: connect-ui init NEW_DIR http://127.0.0.1:17891 TOKEN_FILE | serve ui.json | password ui.json")
	}
	var c panel.Config
	if e := management.ReadJSON(os.Args[2], &c); e != nil {
		return e
	}
	if os.Args[1] == "password" {
		password, e := readPassword()
		if e != nil {
			return e
		}
		c.Salt = management.Random()
		c.PasswordHash, e = panel.Password(password, c.Salt)
		if e != nil {
			return e
		}
		if e = management.WriteJSON(os.Args[2], c); e != nil {
			return e
		}
		fmt.Println("Password saved. Restart CONNECT UI to apply and invalidate all sessions.")
		return nil
	}
	if os.Args[1] != "serve" {
		return fmt.Errorf("unknown command")
	}
	p, e := panel.New(c)
	if e != nil {
		return e
	}
	l, e := net.Listen("tcp", c.Listen)
	if e != nil {
		return e
	}
	defer l.Close()
	s := &http.Server{Handler: p, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 25 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
	s.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	go func() {
		<-ctx.Done()
		c, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		s.Shutdown(c)
	}()
	scheme := "http"
	if c.TLSCert != "" {
		scheme = "https"
	}
	fmt.Printf("CONNECT UI %s ready at %s://%s\n", management.Version, scheme, l.Addr())
	if c.TLSCert != "" {
		e = s.ServeTLS(l, c.TLSCert, c.TLSKey)
	} else {
		e = s.Serve(l)
	}
	if e == http.ErrServerClosed {
		return nil
	}
	return e
}

// Package core implements the loopback-only CONNECT Protocol experiment.
package core

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const Version = 1
const MaxService = 128
const IdleTimeout = 15 * time.Second

type Config struct {
	Version        int               `json:"config_version"`
	Listen         string            `json:"listen"`
	Server         string            `json:"server,omitempty"`
	ServerName     string            `json:"server_name,omitempty"`
	Service        string            `json:"service,omitempty"`
	CA             string            `json:"ca"`
	Cert           string            `json:"cert"`
	Key            string            `json:"key"`
	AllowedClients []string          `json:"allowed_clients,omitempty"`
	Services       map[string]string `json:"services,omitempty"`
}

func Load(path string) (Config, error) {
	var c Config
	f, err := os.Open(path)
	if err != nil {
		return c, err
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 65537))
	d.DisallowUnknownFields()
	if err = d.Decode(&c); err != nil {
		return c, err
	}
	var extra any
	if err = d.Decode(&extra); err != io.EOF {
		return c, errors.New("trailing configuration data")
	}
	if c.Version != 1 {
		return c, errors.New("unsupported config_version")
	}
	return c, nil
}

// Numeric loopback addresses eliminate DNS and prevent accidental deployment.
func Loopback(address string) error {
	h, p, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(h)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("lab requires numeric loopback addresses")
	}
	port, err := strconv.Atoi(p)
	if err != nil || port < 0 || port > 65535 {
		return errors.New("invalid port")
	}
	return nil
}

func validService(s string) bool {
	if len(s) == 0 || len(s) > MaxService {
		return false
	}
	for _, c := range []byte(s) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func TLS(c Config, server bool) (*tls.Config, error) {
	pair, err := tls.LoadX509KeyPair(c.Cert, c.Key)
	if err != nil {
		return nil, err
	}
	pem, err := os.ReadFile(c.CA)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, errors.New("invalid CA")
	}
	t := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, NextProtos: []string{"connect-lab/1"}, SessionTicketsDisabled: true}
	if server {
		if len(c.AllowedClients) == 0 {
			return nil, errors.New("allowed_clients is required")
		}
		pins := map[string]bool{}
		for _, pin := range c.AllowedClients {
			b, e := hex.DecodeString(pin)
			if e != nil || len(b) != 32 {
				return nil, errors.New("invalid client SHA-256 pin")
			}
			pins[strings.ToLower(pin)] = true
		}
		t.ClientCAs = roots
		t.ClientAuth = tls.RequireAndVerifyClientCert
		t.VerifyConnection = func(s tls.ConnectionState) error {
			if len(s.PeerCertificates) == 0 {
				return errors.New("client certificate missing")
			}
			if !pins[Fingerprint(s.PeerCertificates[0].Raw)] {
				return errors.New("client is not allowed")
			}
			return nil
		}
	} else {
		if c.ServerName == "" {
			return nil, errors.New("server_name is required")
		}
		t.RootCAs = roots
		t.ServerName = c.ServerName
	}
	return t, nil
}

func Fingerprint(der []byte) string { h := sha256.Sum256(der); return hex.EncodeToString(h[:]) }

// Header: magic[4], version[1], operation[1], service length[2] (big endian).
func WriteRequest(w io.Writer, service string) error {
	if !validService(service) {
		return errors.New("invalid service")
	}
	b := make([]byte, 8+len(service))
	copy(b, "CCP0")
	b[4] = Version
	b[5] = 1
	binary.BigEndian.PutUint16(b[6:8], uint16(len(service)))
	copy(b[8:], service)
	return writeAll(w, b)
}
func ReadRequest(r io.Reader) (string, error) {
	var h [8]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return "", err
	}
	if string(h[:4]) != "CCP0" || h[4] != Version || h[5] != 1 {
		return "", errors.New("unsupported protocol")
	}
	n := int(binary.BigEndian.Uint16(h[6:8]))
	if n == 0 || n > MaxService {
		return "", errors.New("invalid service length")
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", err
	}
	if !validService(string(b)) {
		return "", errors.New("invalid service")
	}
	return string(b), nil
}
func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, e := w.Write(b)
		if e != nil {
			return e
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}

type idleConn struct{ net.Conn }

func (c idleConn) Read(b []byte) (int, error) {
	_ = c.SetReadDeadline(time.Now().Add(IdleTimeout))
	return c.Conn.Read(b)
}
func (c idleConn) Write(b []byte) (int, error) {
	_ = c.SetWriteDeadline(time.Now().Add(IdleTimeout))
	return c.Conn.Write(b)
}

func Relay(a, b net.Conn) {
	defer a.Close()
	defer b.Close()
	var wg sync.WaitGroup
	wg.Add(2)
	pump := func(dst, src net.Conn) {
		defer wg.Done()
		_, err := io.Copy(idleConn{dst}, idleConn{src})
		if err != nil {
			_ = a.Close()
			_ = b.Close()
			return
		}
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.Close()
		}
	}
	go pump(a, b)
	go pump(b, a)
	wg.Wait()
}

func Dial(ctx context.Context, address, service string, t *tls.Config) (net.Conn, error) {
	if err := Loopback(address); err != nil {
		return nil, err
	}
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second}, Config: t}
	conn, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	tc := conn.(*tls.Conn)
	if tc.ConnectionState().NegotiatedProtocol != "connect-lab/1" {
		conn.Close()
		return nil, errors.New("ALPN mismatch")
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err = WriteRequest(conn, service); err != nil {
		conn.Close()
		return nil, err
	}
	var reply [2]byte
	_, err = io.ReadFull(conn, reply[:])
	if err != nil || reply[0] != Version || reply[1] != 0 {
		conn.Close()
		return nil, fmt.Errorf("service rejected: %v", err)
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

// Serve bounds active handlers before TLS handshake, and waits on cancellation.
func Serve(ctx context.Context, l net.Listener, t *tls.Config, services map[string]string) error {
	if len(services) == 0 || len(services) > 64 {
		return errors.New("lab requires 1..64 services")
	}
	for s, a := range services {
		if !validService(s) {
			return errors.New("invalid service name")
		}
		if err := Loopback(a); err != nil {
			return err
		}
	}
	return accept(ctx, l, func(raw net.Conn) {
		conn := tls.Server(raw, t)
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if conn.HandshakeContext(ctx) != nil || conn.ConnectionState().NegotiatedProtocol != "connect-lab/1" {
			return
		}
		service, err := ReadRequest(conn)
		if err != nil {
			return
		}
		address, ok := services[service]
		if !ok {
			_ = writeAll(conn, []byte{Version, 1})
			return
		}
		target, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", address)
		if err != nil {
			_ = writeAll(conn, []byte{Version, 2})
			return
		}
		defer target.Close()
		if writeAll(conn, []byte{Version, 0}) != nil {
			return
		}
		_ = conn.SetDeadline(time.Time{})
		Relay(conn, target)
	})
}

func Forward(ctx context.Context, l net.Listener, address, service string, t *tls.Config) error {
	if err := Loopback(address); err != nil {
		return err
	}
	if !validService(service) {
		return errors.New("invalid service")
	}
	return accept(ctx, l, func(local net.Conn) {
		remote, err := Dial(ctx, address, service, t)
		if err != nil {
			return
		}
		Relay(local, remote)
	})
}

func accept(ctx context.Context, l net.Listener, handler func(net.Conn)) error {
	if err := Loopback(l.Addr().String()); err != nil {
		return err
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	active := map[net.Conn]bool{}
	slots := make(chan struct{}, 32)
	stop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = l.Close()
			mu.Lock()
			for c := range active {
				_ = c.Close()
			}
			mu.Unlock()
		case <-stop:
		}
	}()
	defer func() {
		close(stop)
		mu.Lock()
		for c := range active {
			_ = c.Close()
		}
		mu.Unlock()
		wg.Wait()
	}()
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case slots <- struct{}{}:
		default:
			c.Close()
			continue
		}
		mu.Lock()
		if ctx.Err() != nil {
			mu.Unlock()
			c.Close()
			<-slots
			return nil
		}
		active[c] = true
		mu.Unlock()
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { c.Close(); mu.Lock(); delete(active, c); mu.Unlock(); <-slots }()
			handler(c)
		}()
	}
}

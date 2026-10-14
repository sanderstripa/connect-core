package panel

import (
	"bytes"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/sanderstripa/connect-core/internal/core"
	"github.com/sanderstripa/connect-core/internal/management"
	"golang.org/x/crypto/scrypt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

//go:embed web/*
var assets embed.FS

type Config struct {
	Listen       string `json:"listen"`
	CoreURL      string `json:"core_url"`
	TokenFile    string `json:"token_file"`
	Username     string `json:"username"`
	Salt         string `json:"salt"`
	PasswordHash string `json:"password_hash"`
	TLSCert      string `json:"tls_cert,omitempty"`
	TLSKey       string `json:"tls_key,omitempty"`
	PublicHTTPS  bool   `json:"public_https,omitempty"`
}

func Password(password, salt string) (string, error) {
	b, e := hex.DecodeString(salt)
	if e != nil || len(b) != 32 {
		return "", errors.New("invalid salt")
	}
	key, e := scrypt.Key([]byte(password), b, 32768, 8, 1, 32)
	return hex.EncodeToString(key), e
}

type session struct {
	CSRF    string
	Expires time.Time
}
type limit struct {
	Count int
	Until time.Time
}
type Panel struct {
	cfg                 Config
	token, origin, host string
	secure              bool
	mu                  sync.Mutex
	sessions            map[string]session
	attempts            map[string]limit
	client              *http.Client
	loginSlots          chan struct{}
}

func New(c Config) (*Panel, error) {
	if e := core.Loopback(c.Listen); e != nil {
		host, port, err := net.SplitHostPort(c.Listen)
		ip := net.ParseIP(host)
		if !c.PublicHTTPS || c.TLSCert == "" || c.TLSKey == "" || err != nil || ip == nil || ip.To4() == nil || ip.IsUnspecified() || ip.IsMulticast() || port == "0" {
			return nil, errors.New("public panel requires explicit HTTPS, TLS paths and an assigned numeric IPv4")
		}
	}
	u, e := url.Parse(c.CoreURL)
	if e != nil || u.Scheme != "http" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || core.Loopback(u.Host) != nil {
		return nil, errors.New("core URL must be numeric loopback HTTP")
	}
	b, e := os.ReadFile(c.TokenFile)
	if e != nil {
		return nil, e
	}
	token := strings.TrimSpace(string(b))
	if len(token) != 64 {
		return nil, errors.New("invalid control token")
	}
	h, e := hex.DecodeString(c.PasswordHash)
	if e != nil || len(h) != 32 || c.Username == "" {
		return nil, errors.New("invalid credentials")
	}
	if _, e = Password("", c.Salt); e != nil {
		return nil, e
	}
	secure := c.TLSCert != ""
	if secure != (c.TLSKey != "") {
		return nil, errors.New("both TLS paths required")
	}
	if c.PublicHTTPS && !secure {
		return nil, errors.New("public panel cannot serve plaintext HTTP")
	}
	scheme := "http"
	if secure {
		scheme = "https"
	}
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext, MaxIdleConnsPerHost: 4}
	host := c.Listen
	if secure {
		if h, port, err := net.SplitHostPort(host); err == nil && port == "443" {
			host = h
		}
	}
	return &Panel{cfg: c, token: token, host: host, origin: scheme + "://" + host, secure: secure, sessions: map[string]session{}, attempts: map[string]limit{}, loginSlots: make(chan struct{}, 4), client: &http.Client{Timeout: 20 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (p *Panel) cookie(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: "connect_session", Value: value, Path: "/", HttpOnly: true, Secure: p.secure, SameSite: http.SameSiteStrictMode, MaxAge: maxAge})
}
func (p *Panel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	if p.secure {
		w.Header().Set("Strict-Transport-Security", "max-age=86400")
	}
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	errJSON := func(code int, s string) { management.JSON(w, code, map[string]string{"error": s}) }
	if r.Host != p.host && r.Host != p.cfg.Listen {
		errJSON(403, "invalid host")
		return
	}
	origin := r.Header.Get("Origin")
	if p.secure && strings.HasSuffix(p.cfg.Listen, ":443") && origin == "https://"+p.cfg.Listen {
		origin = p.origin
	}
	if r.Method != "GET" && (origin != p.origin || r.Header.Get("X-Connect-UI") != "1") {
		errJSON(403, "same-origin request required")
		return
	}
	if r.Method == "POST" && r.URL.Path == "/auth/login" {
		select {
		case p.loginSlots <- struct{}{}:
			defer func() { <-p.loginSlots }()
		default:
			errJSON(429, "login capacity reached")
			return
		}
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		p.mu.Lock()
		if len(p.attempts) >= 4096 {
			for key, value := range p.attempts {
				if time.Now().After(value.Until) {
					delete(p.attempts, key)
				}
			}
			if _, known := p.attempts[ip]; !known && len(p.attempts) >= 4096 {
				p.mu.Unlock()
				errJSON(429, "login capacity reached")
				return
			}
		}
		a := p.attempts[ip]
		if time.Now().After(a.Until) {
			a = limit{Until: time.Now().Add(time.Minute)}
		}
		a.Count++
		p.attempts[ip] = a
		p.mu.Unlock()
		if a.Count > 5 {
			w.Header().Set("Retry-After", "60")
			errJSON(429, "too many login attempts")
			return
		}
		var v struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if management.Decode(w, r, &v) != nil || len(v.Password) > 1024 {
			errJSON(400, "invalid login")
			return
		}
		hash, e := Password(v.Password, p.cfg.Salt)
		if e != nil || subtle.ConstantTimeCompare([]byte(hash), []byte(p.cfg.PasswordHash)) != 1 || subtle.ConstantTimeCompare([]byte(v.Username), []byte(p.cfg.Username)) != 1 {
			errJSON(401, "invalid credentials")
			return
		}
		sid, csrf := management.Random(), management.Random()
		p.mu.Lock()
		for k, s := range p.sessions {
			if time.Now().After(s.Expires) {
				delete(p.sessions, k)
			}
		}
		if len(p.sessions) >= 32 {
			p.mu.Unlock()
			errJSON(429, "session limit reached")
			return
		}
		p.sessions[sid] = session{csrf, time.Now().Add(8 * time.Hour)}
		p.mu.Unlock()
		p.cookie(w, sid, 28800)
		management.JSON(w, 200, map[string]string{"csrf": csrf, "role": "administrator"})
		return
	}
	if r.Method == "GET" && (r.URL.Path == "/" || r.URL.Path == "/app.js" || r.URL.Path == "/style.css") {
		file := strings.TrimPrefix(r.URL.Path, "/")
		if file == "" {
			file = "index.html"
		}
		b, e := assets.ReadFile("web/" + file)
		if e != nil {
			errJSON(404, "not found")
			return
		}
		switch file {
		case "index.html":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
		case "app.js":
			w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		case "style.css":
			w.Header().Set("Content-Type", "text/css; charset=utf-8")
		}
		w.Write(b)
		return
	}
	c, _ := r.Cookie("connect_session")
	sid := ""
	if c != nil {
		sid = c.Value
	}
	p.mu.Lock()
	s, ok := p.sessions[sid]
	if ok && time.Now().After(s.Expires) {
		delete(p.sessions, sid)
		ok = false
	}
	p.mu.Unlock()
	if !ok {
		errJSON(401, "authentication required")
		return
	}
	if r.Method != "GET" && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(s.CSRF)) != 1 {
		errJSON(403, "CSRF token required")
		return
	}
	if r.Method == "GET" && r.URL.Path == "/auth/session" {
		management.JSON(w, 200, map[string]string{"csrf": s.CSRF, "role": "administrator"})
		return
	}
	if r.Method == "POST" && r.URL.Path == "/auth/logout" {
		p.mu.Lock()
		delete(p.sessions, sid)
		p.mu.Unlock()
		p.cookie(w, "", -1)
		management.JSON(w, 200, map[string]bool{"ok": true})
		return
	}
	if r.Method == "POST" && r.URL.Path == "/auth/password" {
		var v struct {
			Current  string `json:"current"`
			Password string `json:"password"`
		}
		if management.Decode(w, r, &v) != nil || len(v.Password) < 12 || len(v.Password) > 1024 {
			errJSON(400, "new password must contain 12..1024 bytes")
			return
		}
		// Password changes are handled by the CLI to atomically persist credentials
		// and invalidate every session on restart, not by a volatile API setting.
		errJSON(409, "use connect-ui password ui.json and restart panel to revoke all sessions")
		return
	}
	path := r.URL.Path
	allowed := r.Method == "GET" && (path == "/api/status" || path == "/api/logs" || path == "/api/challenge" || path == "/api/ca" || path == "/api/registrations" || strings.HasPrefix(path, "/api/export/") || strings.HasPrefix(path, "/api/certificate/")) || r.Method == "POST" && (path == "/api/server" || path == "/api/device" || path == "/api/enroll" || path == "/api/settings" || path == "/api/invite" || path == "/api/registration")
	if !allowed {
		errJSON(404, "unsupported route or method")
		return
	}
	b, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 65536))
	if e != nil {
		errJSON(400, "request too large")
		return
	}
	req, e := http.NewRequestWithContext(r.Context(), r.Method, p.cfg.CoreURL+"/v1/"+strings.TrimPrefix(path, "/api/"), bytes.NewReader(b))
	if e != nil {
		errJSON(400, "invalid request")
		return
	}
	req.Header.Set("Authorization", "Bearer "+p.token)
	req.Header.Set("Content-Type", "application/json")
	resp, e := p.client.Do(req)
	if e != nil {
		errJSON(502, "CONNECT control unavailable; server state is unknown")
		return
	}
	defer resp.Body.Close()
	body, e := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if e != nil {
		errJSON(502, "control response failed")
		return
	}
	if path == "/api/status" && resp.StatusCode == 200 {
		var v struct {
			Version int `json:"api_version"`
		}
		if json.Unmarshal(body, &v) != nil || v.Version != management.APIVersion {
			errJSON(502, "incompatible control API")
			return
		}
	}
	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	if strings.HasPrefix(path, "/api/export/") {
		w.Header().Set("Content-Disposition", "attachment; filename=connect-ip-client.json")
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(body)
}

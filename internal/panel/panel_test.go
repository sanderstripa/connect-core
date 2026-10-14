package panel

import (
	"encoding/json"
	"fmt"
	"github.com/sanderstripa/connect-core/internal/management"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func setup(t *testing.T) *Panel {
	t.Helper()
	token := management.Random()
	path := filepath.Join(t.TempDir(), "token")
	os.WriteFile(path, []byte(token), 0600)
	salt := management.Random()
	hash, e := Password("test-password-long", salt)
	if e != nil {
		t.Fatal(e)
	}
	p, e := New(Config{Listen: "127.0.0.1:17890", CoreURL: "http://127.0.0.1:17891", TokenFile: path, Username: "admin", Salt: salt, PasswordHash: hash})
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func req(p *Panel, method, path, body, sid, csrf, origin string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, p.origin+path, strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:12345"
	if sid != "" {
		r.AddCookie(&http.Cookie{Name: "connect_session", Value: sid})
	}
	if origin != "" {
		r.Header.Set("Origin", origin)
		r.Header.Set("X-Connect-UI", "1")
	}
	r.Header.Set("X-CSRF-Token", csrf)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	return w
}
func login(t *testing.T, p *Panel) (string, string) {
	t.Helper()
	w := req(p, "POST", "/auth/login", `{"username":"admin","password":"test-password-long"}`, "", "", p.origin)
	if w.Code != 200 {
		t.Fatalf("login failed %d %s", w.Code, w.Body.String())
	}
	var data map[string]string
	json.Unmarshal(w.Body.Bytes(), &data)
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode || cookies[0].Secure != p.secure {
		t.Fatal("unsafe cookie")
	}
	return cookies[0].Value, data["csrf"]
}
func TestAuthorizationCSRFExpiryLogout(t *testing.T) {
	p := setup(t)
	for _, path := range []string{"/api/status", "/api/logs", "/api/export/foo", "/auth/session"} {
		if req(p, "GET", path, "", "", "", "").Code != 401 {
			t.Fatal("unauthenticated API")
		}
	}
	if req(p, "POST", "/auth/login", `{"username":"admin","password":"test-password-long"}`, "", "", "http://evil.example").Code != 403 {
		t.Fatal("login CSRF")
	}
	sid, csrf := login(t, p)
	if req(p, "GET", "/auth/session", "", sid, "", "").Code != 200 {
		t.Fatal("session unavailable")
	}
	for _, v := range []struct{ token, origin string }{{"", p.origin}, {csrf, "http://evil.example"}, {csrf, ""}} {
		if req(p, "POST", "/auth/logout", "{}", sid, v.token, v.origin).Code != 403 {
			t.Fatal("CSRF bypass")
		}
	}
	if req(p, "POST", "/auth/logout", "{}", sid, csrf, p.origin).Code != 200 || req(p, "GET", "/auth/session", "", sid, "", "").Code != 401 {
		t.Fatal("logout did not revoke session")
	}
	sid, csrf = login(t, p)
	p.mu.Lock()
	p.sessions[sid] = session{csrf, time.Now().Add(-time.Second)}
	p.mu.Unlock()
	if req(p, "GET", "/auth/session", "", sid, "", "").Code != 401 {
		t.Fatal("expired session accepted")
	}
	r := httptest.NewRequest("GET", "http://evil.example/", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("DNS rebinding")
	}
}
func TestRateLimitAndSecureCookie(t *testing.T) {
	p := setup(t)
	for i := 0; i < 5; i++ {
		if req(p, "POST", "/auth/login", `{"username":"admin","password":"wrong"}`, "", "", p.origin).Code != 401 {
			t.Fatal("invalid password allowed")
		}
	}
	if req(p, "POST", "/auth/login", `{"username":"admin","password":"test-password-long"}`, "", "", p.origin).Code != 429 {
		t.Fatal("login rate limit bypass")
	}
	p = setup(t)
	p.secure = true
	p.origin = "https://" + p.host
	login(t, p)
}
func TestProxyProtectsTokenAndVersion(t *testing.T) {
	p := setup(t)
	var version atomic.Int64
	version.Store(1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+p.token || r.Header.Get("Cookie") != "" || r.Header.Get("Origin") != "" {
			t.Error("unsafe proxy headers")
		}
		management.JSON(w, 200, map[string]any{"api_version": version.Load(), "status": "stopped"})
	}))
	defer backend.Close()
	p.cfg.CoreURL = backend.URL
	sid, csrf := login(t, p)
	w := req(p, "GET", "/api/status", "", sid, "", "")
	if w.Code != 200 || strings.Contains(w.Body.String(), p.token) {
		t.Fatal("proxy failed/leaked token")
	}
	version.Store(99)
	if req(p, "GET", "/api/status", "", sid, "", "").Code != 502 {
		t.Fatal("incompatible API accepted")
	}
	if req(p, "POST", "/api/settings", "{}", sid, "", p.origin).Code != 403 {
		t.Fatal("proxy API lacks CSRF")
	}
	if req(p, "POST", "/api/not-supported", "{}", sid, csrf, p.origin).Code != 404 {
		t.Fatal("unrestricted proxy")
	}
	backend.Close()
	if req(p, "GET", "/api/status", "", sid, "", "").Code != 502 {
		t.Fatal("offline core displayed success")
	}
}
func TestRejectPublicListeners(t *testing.T) {
	p := setup(t)
	c := p.cfg
	c.Listen = "0.0.0.0:17890"
	if _, e := New(c); e == nil {
		t.Fatal("public panel listener allowed")
	}
	c = p.cfg
	c.CoreURL = "http://example.com:17891"
	if _, e := New(c); e == nil {
		t.Fatal("remote administrative API allowed")
	}
}

func TestPublicHTTPSRequiresExplicitTLSAndCanonicalOrigin(t *testing.T) {
	p := setup(t)
	c := p.cfg
	c.Listen = "198.51.100.20:443"
	c.PublicHTTPS = true
	if _, err := New(c); err == nil {
		t.Fatal("plaintext public panel allowed")
	}
	c.TLSCert, c.TLSKey = "cert.pem", "key.pem"
	p, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	if p.origin != "https://198.51.100.20" {
		t.Fatal(p.origin)
	}
	for _, host := range []string{"198.51.100.20", "198.51.100.20:443"} {
		r := httptest.NewRequest("GET", "https://"+host+"/", nil)
		w := httptest.NewRecorder()
		p.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatal(host, w.Code)
		}
	}
	r := httptest.NewRequest("GET", "https://foreign.example/", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("foreign Host accepted")
	}
	c.PublicHTTPS = false
	if _, err := New(c); err == nil {
		t.Fatal("implicit public exposure allowed")
	}
}

func TestLoginWorkAndIPRegistryAreBounded(t *testing.T) {
	p := setup(t)
	for i := 0; i < cap(p.loginSlots); i++ {
		p.loginSlots <- struct{}{}
	}
	if req(p, "POST", "/auth/login", `{"username":"admin","password":"password123456"}`, "", "", p.origin).Code != 429 {
		t.Fatal("unbounded password hashing")
	}
	for i := 0; i < cap(p.loginSlots); i++ {
		<-p.loginSlots
	}
	for i := 0; i < 4096; i++ {
		p.attempts[fmt.Sprint(i)] = limit{Until: time.Now().Add(time.Minute)}
	}
	if req(p, "POST", "/auth/login", `{}`, "", "", p.origin).Code != 429 {
		t.Fatal("unbounded IP registry")
	}
	if len(p.attempts) != 4096 {
		t.Fatal("IP registry expanded")
	}
}

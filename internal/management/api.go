package management

import (
	"crypto/subtle"
	"encoding/json"
	"github.com/sanderstripa/connect-core/internal/access"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type API struct {
	Manager    *Manager
	Token      string
	Host       string
	mu         sync.Mutex
	challenges map[string]time.Time
	Issuance   *Issuance
}

func JSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func Decode(w http.ResponseWriter, r *http.Request, v any) error {
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 65536))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return e
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Host != a.Host || r.Header.Get("Origin") != "" || len(a.Token) != 64 || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+a.Token)) != 1 {
		JSON(w, 401, map[string]string{"error": "unauthorized"})
		return
	}
	fail := func(e error) { JSON(w, 409, map[string]string{"error": e.Error()}) }
	if r.Method == "GET" {
		switch r.URL.Path {
		case "/v1/status":
			JSON(w, 200, a.Manager.Snapshot())
			return
		case "/v1/logs":
			JSON(w, 200, a.Manager.Logs())
			return
		case "/v1/challenge":
			a.mu.Lock()
			if a.challenges == nil {
				a.challenges = map[string]time.Time{}
			}
			for k, t := range a.challenges {
				if time.Since(t) > 5*time.Minute {
					delete(a.challenges, k)
				}
			}
			if len(a.challenges) >= 32 {
				a.mu.Unlock()
				JSON(w, 429, map[string]string{"error": "too many pending challenges"})
				return
			}
			s := Random()
			a.challenges[s] = time.Now()
			a.mu.Unlock()
			JSON(w, 200, map[string]string{"challenge": s})
			return
		case "/v1/ca":
			b, e := a.Manager.CA()
			if e != nil {
				fail(e)
				return
			}
			w.Header().Set("Content-Type", "application/x-pem-file")
			w.Write(b)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/v1/export/") {
			id := strings.TrimPrefix(r.URL.Path, "/v1/export/")
			b, e := a.Manager.Export(id)
			if e != nil {
				fail(e)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write(b)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/v1/certificate/") {
			b, e := a.Manager.PublicCertificate(strings.TrimPrefix(r.URL.Path, "/v1/certificate/"))
			if e != nil {
				fail(e)
				return
			}
			w.Header().Set("Content-Type", "application/x-pem-file")
			io.WriteString(w, b)
			return
		}
	}
	if r.Method == "POST" {
		switch r.URL.Path {
		case "/v1/invitation":
			if a.Issuance == nil {
				JSON(w, 409, map[string]string{"error": "automatic issuance is not configured"})
				return
			}
			var v struct {
				Name string `json:"name"`
				IP   string `json:"ip"`
			}
			if Decode(w, r, &v) != nil {
				JSON(w, 400, map[string]string{"error": "invalid invitation"})
				return
			}
			link, e := a.Issuance.Invite(v.Name, v.IP)
			if e != nil {
				fail(e)
				return
			}
			JSON(w, 200, map[string]any{"link": link, "expires_in": 300})
			return
		case "/v1/invitation-qr":
			var v struct {
				Link string `json:"link"`
			}
			if Decode(w, r, &v) != nil {
				JSON(w, 400, map[string]string{"error": "invalid invitation"})
				return
			}
			png, e := access.QR(v.Link)
			if e != nil {
				JSON(w, 400, map[string]string{"error": "invalid invitation"})
				return
			}
			w.Header().Set("Content-Type", "image/png")
			w.Write(png)
			return
		case "/v1/server":
			var v struct {
				Action  string `json:"action"`
				Confirm bool   `json:"confirm"`
			}
			if Decode(w, r, &v) != nil {
				JSON(w, 400, map[string]string{"error": "invalid request"})
				return
			}
			var e error
			switch v.Action {
			case "start":
				e = a.Manager.Start()
			case "stop", "restart":
				if !v.Confirm {
					JSON(w, 400, map[string]string{"error": "confirmation required"})
					return
				}
				e = a.Manager.Stop()
				if e == nil && v.Action == "restart" {
					e = a.Manager.Start()
				}
			default:
				JSON(w, 400, map[string]string{"error": "invalid action"})
				return
			}
			if e != nil {
				fail(e)
				return
			}
			JSON(w, 200, a.Manager.Snapshot())
			return
		case "/v1/device":
			var v struct {
				ID      string `json:"id"`
				Action  string `json:"action"`
				Name    string `json:"name"`
				Confirm bool   `json:"confirm"`
			}
			if Decode(w, r, &v) != nil {
				JSON(w, 400, map[string]string{"error": "invalid request"})
				return
			}
			if v.Action != "rename" && !v.Confirm {
				JSON(w, 400, map[string]string{"error": "confirmation required"})
				return
			}
			if e := a.Manager.Change(v.ID, v.Action, v.Name); e != nil {
				fail(e)
				return
			}
			JSON(w, 200, map[string]bool{"ok": true})
			return
		case "/v1/enroll":
			var e Enrollment
			if Decode(w, r, &e) != nil {
				JSON(w, 400, map[string]string{"error": "invalid enrollment"})
				return
			}
			a.mu.Lock()
			t, ok := a.challenges[e.Challenge]
			delete(a.challenges, e.Challenge)
			a.mu.Unlock()
			if !ok || time.Since(t) > 5*time.Minute {
				JSON(w, 400, map[string]string{"error": "challenge expired or consumed"})
				return
			}
			id, err := a.Manager.Enroll(e)
			if err != nil {
				fail(err)
				return
			}
			JSON(w, 200, map[string]string{"id": id})
			return
		case "/v1/settings":
			var v Settings
			if Decode(w, r, &v) != nil {
				JSON(w, 400, map[string]string{"error": "invalid settings"})
				return
			}
			if e := a.Manager.Configure(v); e != nil {
				fail(e)
				return
			}
			JSON(w, 200, map[string]bool{"ok": true})
			return
		}
	}
	JSON(w, 404, map[string]string{"error": "unsupported API route or method"})
}

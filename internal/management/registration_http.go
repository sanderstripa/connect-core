package management

import (
	"net/http"
	"sync"
	"time"
)

type RegistrationAPI struct {
	Broker *Broker
	Host   string
	mu     sync.Mutex
	window time.Time
	count  int
	slots  chan struct{}
}

func (a *RegistrationAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Host != a.Host || r.Header.Get("Origin") != "" {
		JSON(w, 403, map[string]string{"error": "native registration client required"})
		return
	}
	if r.Method == "GET" && r.URL.Path == "/health" {
		JSON(w, 200, map[string]int{"import_version": 1})
		return
	}
	if r.Method != "POST" || (r.URL.Path != "/register" && r.URL.Path != "/result") || r.URL.RawQuery != "" {
		JSON(w, 404, map[string]string{"error": "not found"})
		return
	}
	a.mu.Lock()
	if time.Since(a.window) > time.Minute {
		a.window = time.Now()
		a.count = 0
	}
	a.count++
	if a.slots == nil {
		a.slots = make(chan struct{}, 8)
	}
	allowed := a.count <= 300
	slots := a.slots
	a.mu.Unlock()
	if !allowed {
		JSON(w, 429, map[string]string{"error": "registration rate limit"})
		return
	}
	select {
	case slots <- struct{}{}:
		defer func() { <-slots }()
	default:
		JSON(w, 429, map[string]string{"error": "registration busy"})
		return
	}
	var v Registration
	if Decode(w, r, &v) != nil {
		JSON(w, 400, map[string]string{"error": "invalid registration"})
		return
	}
	result, e := a.Broker.Result(v)
	if e != nil {
		JSON(w, 409, map[string]string{"error": e.Error()})
		return
	}
	JSON(w, 200, result)
}

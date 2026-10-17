package management

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAPIBoundary(t *testing.T) {
	m, _, id := fixture(t)
	api := &API{Manager: m, Token: Random(), Host: "127.0.0.1:17891"}
	request := func(method, path, body, token, origin, host string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://"+host+path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		api.ServeHTTP(w, r)
		return w
	}
	for _, v := range []struct{ token, origin, host string }{{"", "", api.Host}, {Random(), "", api.Host}, {api.Token, "http://evil.example", api.Host}, {api.Token, "", "evil.example"}} {
		if w := request("GET", "/v1/status", "", v.token, v.origin, v.host); w.Code != 401 {
			t.Fatalf("auth bypass %d", w.Code)
		}
	}
	w := request("GET", "/v1/status", "", api.Token, "", api.Host)
	if request("GET", "/v1/diagnostics", "", "", "", api.Host).Code != 401 {
		t.Fatal("unauthenticated diagnostics")
	}
	if d := request("GET", "/v1/diagnostics", "", api.Token, "", api.Host); d.Code != 200 || !strings.Contains(d.Body.String(), `"samples"`) {
		t.Fatal("authorized diagnostics unavailable")
	}
	if w.Code != 200 || strings.Contains(w.Body.String(), m.state.Config.Trust.Key) {
		t.Fatal("unsafe status")
	}
	for _, body := range []string{`{"action":"stop"}`, `{"action":"restart"}`, `{"action":"start","unknown":1}`, `{"action":"start"} {}`} {
		if w = request("POST", "/v1/server", body, api.Token, "", api.Host); w.Code != 400 {
			t.Fatalf("invalid server request accepted: %s %d", body, w.Code)
		}
	}
	if w = request("POST", "/v1/device", `{"id":"`+id+`","action":"revoke"}`, api.Token, "", api.Host); w.Code != 400 {
		t.Fatal("missing dangerous action confirmation")
	}
	w = request("GET", "/v1/challenge", "", api.Token, "", api.Host)
	var challenge map[string]string
	json.Unmarshal(w.Body.Bytes(), &challenge)
	body := `{"name":"test","ip":"10.231.0.3","challenge":"` + challenge["challenge"] + `","csr":"invalid","certificate":"invalid"}`
	if w = request("POST", "/v1/enroll", body, api.Token, "", api.Host); w.Code != 409 {
		t.Fatal("invalid proof accepted")
	}
	if w = request("POST", "/v1/enroll", body, api.Token, "", api.Host); w.Code != 400 {
		t.Fatal("challenge replay accepted")
	}
	for i := 0; i < 32; i++ {
		request("GET", "/v1/challenge", "", api.Token, "", api.Host)
	}
	if request("GET", "/v1/challenge", "", api.Token, "", api.Host).Code != 429 {
		t.Fatal("unbounded challenge registry")
	}
	if request("DELETE", "/v1/device", "", api.Token, "", api.Host).Code != 404 {
		t.Fatal("unsupported API method")
	}
}

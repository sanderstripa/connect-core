package access

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRedeemRejectsInvalidInvitationBeforeNetwork(t *testing.T) {
	for _, i := range []Invitation{{}, {URL: "://bad"}, {URL: "http://localhost/enroll", Pin: strings.Repeat("a", 64), Token: strings.Repeat("b", 64)}} {
		if _, err := Redeem(context.Background(), i, "CSR"); err == nil {
			t.Fatal("invalid invitation accepted")
		}
	}
}

func TestInvitationAndQR(t *testing.T) {
	i := Invitation{URL: "https://127.0.0.1:17892/enroll", Pin: strings.Repeat("a", 64), Token: strings.Repeat("b", 64)}
	s, e := Link(i)
	if e != nil {
		t.Fatal(e)
	}
	p, e := Parse(s)
	if e != nil || p != i {
		t.Fatal("link roundtrip")
	}
	for _, bad := range []string{strings.Replace(s, "https%3A", "http%3A", 1), s + "a", s + "&extra=1", strings.Replace(s, "v=1", "v=2", 1), strings.Replace(s, "url=", "url=x&url=", 1), "connect://enroll?token=PRIVATE-KEY"} {
		if _, e = Parse(bad); e == nil {
			t.Fatal("accepted invalid URI")
		}
	}
	png, e := QR(s)
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(t.TempDir(), "invitation.png")
	os.WriteFile(path, png, 0600)
	got, e := ReadQR(path)
	if e != nil || got != s {
		t.Fatalf("real QR roundtrip: %v", e)
	}
	key, csr, e := KeyAndCSR(i.Token)
	if e != nil || len(key) == 0 || len(csr) == 0 {
		t.Fatal("CSR creation")
	}
	if strings.Contains(s, "PRIVATE") || strings.Contains(csr, "PRIVATE KEY") {
		t.Fatal("key escaped invitation")
	}
}

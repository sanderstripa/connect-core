package ipvpn

import "testing"

func TestHostNamespaceRefused(t *testing.T) {
	if isolation() == nil {
		t.Fatal("host namespace was accepted by IP lab")
	}
}

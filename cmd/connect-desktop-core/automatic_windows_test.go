//go:build windows

package main

import (
	"github.com/sanderstripa/connect-core/internal/ipvpn"
	"testing"
)

func TestAutomaticVPNTunneledDNSAndExplicitPolicy(t *testing.T) {
	for _, endpoint := range []string{"8.8.4.4:17444", "1.1.1.1:17444"} {
		c := ipvpn.Config{Environment: "managed-vps", Endpoint: endpoint}
		automaticVPN(&c)
		want := "1.1.1.1"
		if endpoint == "1.1.1.1:17444" {
			want = "9.9.9.9"
		}
		if c.Network == nil || c.Network.Mode != "system-vpn" || c.Network.DNS != want {
			t.Fatal("automatic tunnel DNS missing or conflicts with underlay", c.Network)
		}
		c.Network.DNS = "8.8.8.8"
		automaticVPN(&c)
		if c.Network.DNS != "8.8.8.8" {
			t.Fatal("explicit DNS overwritten")
		}
	}
	c := ipvpn.Config{Environment: "isolated-lab"}
	automaticVPN(&c)
	if c.Network != nil {
		t.Fatal("packet laboratory gained system networking")
	}
}

package ipvpn

import (
	"testing"
)

func TestSystemPolicyIsExplicit(t *testing.T) {
	c := Config{Version: 2, Environment: "isolated-lab", Endpoint: "8.8.8.8:17444", Interface: "ccvpn", DeviceIP: "10.231.0.2", Destinations: []string{"0.0.0.0/0"}, Network: &NetworkPolicy{Mode: "system-vpn", DNS: "10.232.0.1"}}
	p, e := c.Validate(false)
	if e != nil {
		t.Fatal(e)
	}
	if !p[""].Allows(udp("10.231.0.2", "1.1.1.1", nil), true) {
		t.Fatal("system policy did not carry IPv4 default destination")
	}
	old := c
	old.Network = nil
	if _, e = old.Validate(false); e == nil {
		t.Fatal("legacy lab silently broadened")
	}
	for _, endpoint := range []string{"invalid", "[::1]:17444", "server.example:17444", "0.0.0.0:17444"} {
		x := c
		x.Endpoint = endpoint
		if _, e = x.Validate(false); e == nil {
			t.Fatal("invalid system endpoint", endpoint)
		}
	}
	for _, dns := range []string{"127.0.0.1", "::1", "8.8.8.8", "10.231.0.2", "224.0.0.1"} {
		x := c
		x.Network = &NetworkPolicy{Mode: "system-vpn", DNS: dns}
		if _, e = x.Validate(false); e == nil {
			t.Fatal("invalid system DNS", dns)
		}
	}
}

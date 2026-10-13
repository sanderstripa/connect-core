package ipvpn

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"strings"

	"github.com/sanderstripa/connect-core/internal/core"
)

type Config struct {
	Version      int               `json:"config_version"`
	Environment  string            `json:"environment"`
	Endpoint     string            `json:"endpoint"`
	Interface    string            `json:"interface"`
	DeviceIP     string            `json:"device_ip,omitempty"`
	Clients      map[string]string `json:"clients,omitempty"` // Certificate SHA-256 -> assigned IPv4.
	Destinations []string          `json:"destinations"`
	Trust        core.Config       `json:"trust"`
}

func Load(path string) (Config, error) {
	var c Config
	f, e := os.Open(path)
	if e != nil {
		return c, e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return c, e
	}
	if !st.Mode().IsRegular() || st.Size() > 65536 {
		return c, errors.New("config exceeds 64 KiB")
	}
	d := json.NewDecoder(io.LimitReader(f, 65537))
	d.DisallowUnknownFields()
	if e = d.Decode(&c); e != nil {
		return c, e
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return c, errors.New("trailing config data")
	}
	return c, nil
}
func (c Config) Validate(server bool) (map[string]Policy, error) {
	if c.Version != 2 || c.Environment != "isolated-lab" {
		return nil, errors.New("requires config_version 2 and environment isolated-lab")
	}
	ap, e := netip.ParseAddrPort(c.Endpoint)
	if e != nil || !ap.Addr().Is4() || ap.Port() == 0 || !(ap.Addr().IsLoopback() || ap.Addr().IsPrivate()) {
		return nil, errors.New("numeric loopback/private IPv4 lab endpoint required")
	}
	if len(c.Interface) < 1 || len(c.Interface) > 15 {
		return nil, errors.New("interface name must be 1..15 characters")
	}
	for _, b := range []byte(c.Interface) {
		if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '-') {
			return nil, errors.New("invalid interface name")
		}
	}
	if len(c.Destinations) == 0 || len(c.Destinations) > 32 {
		return nil, errors.New("requires 1..32 destination CIDRs")
	}
	var prefixes []netip.Prefix
	for _, s := range c.Destinations {
		p, e := netip.ParsePrefix(s)
		// Narrow private lab networks only: prevent accidental internet/open forwarding.
		if e != nil || !p.Addr().Is4() || !p.Addr().IsPrivate() || p.Bits() < 24 || p != p.Masked() {
			return nil, errors.New("destinations require canonical private IPv4 /24 or narrower")
		}
		if p.Contains(ap.Addr()) {
			return nil, errors.New("endpoint must be outside destination policy")
		}
		prefixes = append(prefixes, p)
	}
	out := map[string]Policy{}
	used := map[netip.Addr]bool{}
	add := func(pin, s string) error {
		ip, e := netip.ParseAddr(s)
		if e != nil || !ip.Is4() || !ip.IsPrivate() || !unicast(ip) {
			return errors.New("private unicast device IPv4 required")
		}
		if used[ip] || ip == ap.Addr() {
			return errors.New("duplicate device/endpoint IP")
		}
		for _, p := range prefixes {
			if p.Contains(ip) {
				return errors.New("device IP overlaps destinations")
			}
		}
		used[ip] = true
		out[pin] = Policy{ip, prefixes}
		return nil
	}
	if server {
		if len(c.Clients) < 1 || len(c.Clients) > 32 {
			return nil, errors.New("requires 1..32 certificate/address bindings")
		}
		for pin, ip := range c.Clients {
			b, e := hex.DecodeString(pin)
			if e != nil || len(b) != 32 || pin != strings.ToLower(pin) {
				return nil, errors.New("canonical lowercase SHA-256 pin required")
			}
			if e = add(pin, ip); e != nil {
				return nil, e
			}
		}
	} else {
		if e = add("", c.DeviceIP); e != nil {
			return nil, e
		}
	}
	return out, nil
}

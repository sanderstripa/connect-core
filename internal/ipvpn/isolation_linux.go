package ipvpn

import (
	"errors"
	"os"
)

// Refuse the host network namespace. No routes, DNS, NAT or firewall are changed
// by the engine; the test harness owns all network configuration in namespaces.
func isolation() error {
	self, e := os.Readlink("/proc/self/ns/net")
	if e != nil {
		return e
	}
	host, e := os.Readlink("/proc/1/ns/net")
	if e != nil {
		return e
	}
	if self == host {
		return errors.New("IP lab requires a disposable network namespace; host namespace refused")
	}
	return nil
}

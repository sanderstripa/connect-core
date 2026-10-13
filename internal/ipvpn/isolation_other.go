//go:build !linux && !windows

package ipvpn

import "errors"

func isolation() error {
	return errors.New("IP lab supports Linux namespaces and isolated Windows VMs only")
}

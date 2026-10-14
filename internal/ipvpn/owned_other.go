//go:build !linux

package ipvpn

import "errors"

func OpenOwned(string) (Device, error) { return nil, errors.New("managed VPS TUN requires Linux") }

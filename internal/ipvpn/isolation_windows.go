package ipvpn

import (
	"errors"
	"os"
)

// An explicit VM-only opt-in: it is not a security boundary or VM detector.
func isolation() error {
	if os.Getenv("CONNECT_IP_LAB_VM") != "1" {
		return errors.New("Wintun lab requires an isolated Windows VM and CONNECT_IP_LAB_VM=1")
	}
	return nil
}

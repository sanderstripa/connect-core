//go:build !windows

package onboarding

import (
	"errors"
	"os"
)

func protectDirectory(path string) error {
	st, e := os.Stat(path)
	if e != nil {
		return e
	}
	if !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		return errors.New("client directory must be private (0700)")
	}
	return nil
}

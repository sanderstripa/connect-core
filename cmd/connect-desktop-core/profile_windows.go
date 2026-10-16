//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime/pprof"
)

// CI-only CPU sampling: no listener, payload capture or workstation activation.
// The VM harness supplies an existing private directory per worker instance.
func startLabCPUProfile() func() {
	dir := os.Getenv("CONNECT_LAB_CPU_PROFILE_DIR")
	if os.Getenv("GITHUB_ACTIONS") != "true" || dir == "" {
		return func() {}
	}
	f, err := os.OpenFile(filepath.Join(dir, fmt.Sprintf("worker-cpu-%d.pprof", os.Getpid())), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Fprintln(os.Stderr, "CONNECT lab CPU profile: create failed")
		return func() {}
	}
	if err = pprof.StartCPUProfile(f); err != nil {
		f.Close()
		fmt.Fprintln(os.Stderr, "CONNECT lab CPU profile: start failed")
		return func() {}
	}
	return func() { pprof.StopCPUProfile(); f.Close() }
}

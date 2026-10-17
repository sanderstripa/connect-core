//go:build !linux && !windows

package management

func processCPUTime() (uint64, bool) { return 0, false }

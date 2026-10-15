//go:build windows

package main

import (
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

func processTimes(handle windows.Handle) (kernel, user uint64, ok bool) {
	var created, exited, k, u windows.Filetime
	if windows.GetProcessTimes(handle, &created, &exited, &k, &u) != nil {
		return 0, 0, false
	}
	// FILETIME is in 100-ns units. Report CPU milliseconds, not wall-clock timestamps.
	return (uint64(k.HighDateTime)<<32 | uint64(k.LowDateTime)) / 10000, (uint64(u.HighDateTime)<<32 | uint64(u.LowDateTime)) / 10000, true
}

func (b *nativeBridge) reportCPU() {
	helper, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, b.helperPID)
	if err == nil {
		defer windows.CloseHandle(helper)
	}
	type sample struct {
		name         string
		handle       windows.Handle
		kernel, user uint64
		valid        bool
	}
	processes := []sample{{name: "worker", handle: windows.CurrentProcess()}}
	if err == nil {
		processes = append(processes, sample{name: "helper", handle: helper})
	}
	for i := range processes {
		p := &processes[i]
		p.kernel, p.user, p.valid = processTimes(p.handle)
	}
	last := time.Now()
	report := func() {
		now := time.Now()
		interval := now.Sub(last).Milliseconds()
		for i := range processes {
			p := &processes[i]
			k, u, ok := processTimes(p.handle)
			if ok && p.valid && k >= p.kernel && u >= p.user {
				fmt.Fprintf(os.Stderr, "CONNECT process CPU: role=%s interval_ms=%d kernel_ms=%d user_ms=%d\n", p.name, interval, k-p.kernel, u-p.user)
			}
			p.kernel, p.user, p.valid = k, u, ok
		}
		last = now
	}
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-b.done:
			report()
			return
		case <-ticker.C:
			report()
		}
	}
}

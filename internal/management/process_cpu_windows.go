package management

import "golang.org/x/sys/windows"

func processCPUTime() (uint64, bool) {
	var created, exited, k, u windows.Filetime
	if windows.GetProcessTimes(windows.CurrentProcess(), &created, &exited, &k, &u) != nil {
		return 0, false
	}
	return ((uint64(k.HighDateTime)<<32 | uint64(k.LowDateTime)) + (uint64(u.HighDateTime)<<32 | uint64(u.LowDateTime))) / 10, true
}

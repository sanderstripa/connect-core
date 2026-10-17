package management

import "golang.org/x/sys/unix"

func processCPUTime() (uint64, bool) {
	var r unix.Rusage
	if unix.Getrusage(unix.RUSAGE_SELF, &r) != nil {
		return 0, false
	}
	return uint64(r.Utime.Sec+r.Stime.Sec)*1000000 + uint64(r.Utime.Usec+r.Stime.Usec), true
}

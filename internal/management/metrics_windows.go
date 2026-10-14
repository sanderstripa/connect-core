package management

import (
	"golang.org/x/sys/windows"
	"sync"
	"unsafe"
)

var metricMu sync.Mutex
var prevTotal, prevIdle uint64
var kernel = windows.NewLazySystemDLL("kernel32.dll")

type memoryStatus struct {
	Length, Load                                                                          uint32
	TotalPhys, AvailPhys, TotalPage, AvailPage, TotalVirtual, AvailVirtual, AvailExtended uint64
}

func SystemMetrics() map[string]any {
	metricMu.Lock()
	defer metricMu.Unlock()
	out := map[string]any{"cpu_percent": nil, "ram_used_bytes": nil, "ram_total_bytes": nil, "disk_used_bytes": nil, "disk_total_bytes": nil, "scope": "host / current filesystem"}
	var idle, kern, user windows.Filetime
	r, _, _ := kernel.NewProc("GetSystemTimes").Call(uintptr(unsafe.Pointer(&idle)), uintptr(unsafe.Pointer(&kern)), uintptr(unsafe.Pointer(&user)))
	n := func(f windows.Filetime) uint64 { return uint64(f.HighDateTime)<<32 | uint64(f.LowDateTime) }
	if r != 0 {
		total, i := n(kern)+n(user), n(idle)
		if prevTotal > 0 && total > prevTotal {
			out["cpu_percent"] = 100 * (1 - float64(i-prevIdle)/float64(total-prevTotal))
		}
		prevTotal = total
		prevIdle = i
	}
	m := memoryStatus{}
	m.Length = uint32(unsafe.Sizeof(m))
	r, _, _ = kernel.NewProc("GlobalMemoryStatusEx").Call(uintptr(unsafe.Pointer(&m)))
	if r != 0 {
		out["ram_total_bytes"] = m.TotalPhys
		out["ram_used_bytes"] = m.TotalPhys - m.AvailPhys
	}
	p, _ := windows.UTF16PtrFromString(".")
	var available, total, free uint64
	r, _, _ = kernel.NewProc("GetDiskFreeSpaceExW").Call(uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&available)), uintptr(unsafe.Pointer(&total)), uintptr(unsafe.Pointer(&free)))
	if r != 0 {
		out["disk_total_bytes"] = total
		out["disk_used_bytes"] = total - free
	}
	return out
}

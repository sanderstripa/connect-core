package management

import (
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"strconv"
	"strings"
	"sync"
)

var metricMu sync.Mutex
var prevTotal, prevIdle uint64

func SystemMetrics() map[string]any {
	metricMu.Lock()
	defer metricMu.Unlock()
	out := map[string]any{"cpu_percent": nil, "ram_used_bytes": nil, "ram_total_bytes": nil, "disk_used_bytes": nil, "disk_total_bytes": nil, "scope": "host / current filesystem"}
	if b, e := os.ReadFile("/proc/stat"); e == nil {
		f := strings.Fields(strings.SplitN(string(b), "\n", 2)[0])
		var total, idle uint64
		for i, s := range f[1:] {
			if i >= 8 {
				break
			}
			v, _ := strconv.ParseUint(s, 10, 64)
			total += v
			if i == 3 || i == 4 {
				idle += v
			}
		}
		if prevTotal > 0 && total > prevTotal {
			out["cpu_percent"] = 100 * (1 - float64(idle-prevIdle)/float64(total-prevTotal))
		}
		prevTotal = total
		prevIdle = idle
	}
	if b, e := os.ReadFile("/proc/meminfo"); e == nil {
		var total, available uint64
		for _, line := range strings.Split(string(b), "\n") {
			var k string
			var v uint64
			fmt.Sscanf(line, "%s %d", &k, &v)
			if k == "MemTotal:" {
				total = v * 1024
			}
			if k == "MemAvailable:" {
				available = v * 1024
			}
		}
		if total > 0 {
			out["ram_total_bytes"] = total
			out["ram_used_bytes"] = total - available
		}
	}
	var st unix.Statfs_t
	if unix.Statfs(".", &st) == nil {
		out["disk_total_bytes"] = st.Blocks * uint64(st.Bsize)
		out["disk_used_bytes"] = (st.Blocks - st.Bfree) * uint64(st.Bsize)
	}
	return out
}

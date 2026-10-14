//go:build !linux && !windows

package management

func SystemMetrics() map[string]any {
	return map[string]any{"cpu_percent": nil, "ram_used_bytes": nil, "ram_total_bytes": nil, "disk_used_bytes": nil, "disk_total_bytes": nil, "scope": "unsupported platform"}
}

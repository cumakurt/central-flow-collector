//go:build !linux

package api

func hostResources() map[string]any {
	return map[string]any{"cpu_error": "Host CPU metrics require Linux", "memory_error": "Host memory metrics require Linux"}
}

//go:build linux

package api

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"sync"
)

var cpuSample struct {
	sync.Mutex
	total, idle uint64
}

func hostResources() map[string]any {
	out := map[string]any{}
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		out["cpu_error"] = err.Error()
	} else {
		fields := strings.Fields(strings.SplitN(string(b), "\n", 2)[0])
		var total, idle uint64
		for i := 1; i < len(fields) && i <= 8; i++ {
			n, _ := strconv.ParseUint(fields[i], 10, 64)
			total += n
			if i == 4 || i == 5 {
				idle += n
			}
		}
		cpuSample.Lock()
		if cpuSample.total > 0 && total > cpuSample.total && idle >= cpuSample.idle {
			dt, di := total-cpuSample.total, idle-cpuSample.idle
			if di <= dt {
				out["cpu_percent"] = 100 * float64(dt-di) / float64(dt)
			}
		}
		cpuSample.total, cpuSample.idle = total, idle
		cpuSample.Unlock()
	}
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		out["memory_error"] = err.Error()
		return out
	}
	defer f.Close()
	mem := map[string]uint64{}
	scan := bufio.NewScanner(f)
	for scan.Scan() {
		fields := strings.Fields(scan.Text())
		if len(fields) >= 2 {
			n, e := strconv.ParseUint(fields[1], 10, 64)
			if e == nil {
				mem[strings.TrimSuffix(fields[0], ":")] = n * 1024
			}
		}
	}
	if err := scan.Err(); err != nil {
		out["memory_error"] = err.Error()
		return out
	}
	total, available := mem["MemTotal"], mem["MemAvailable"]
	if total > 0 && available <= total {
		out["memory_total_bytes"] = total
		out["memory_available_bytes"] = available
		out["memory_used_bytes"] = total - available
		out["memory_percent"] = 100 * float64(total-available) / float64(total)
	} else {
		out["memory_error"] = "Memory metrics unavailable"
	}
	return out
}

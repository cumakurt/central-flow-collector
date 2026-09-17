package storage

// DiskUsage describes space available to the collector on a filesystem.
type DiskUsage struct {
	Path           string  `json:"path"`
	TotalBytes     int64   `json:"total_bytes"`
	UsedBytes      int64   `json:"used_bytes"`
	AvailableBytes int64   `json:"available_bytes"`
	UsedPercent    float64 `json:"used_percent"`
	Error          string  `json:"error,omitempty"`
}

func DiskSpace(path string) DiskUsage {
	free, total := filesystemCapacity(path)
	d := DiskUsage{Path: path, TotalBytes: total, AvailableBytes: free}
	if total <= 0 {
		d.Error = "Filesystem capacity unavailable"
		return d
	}
	// Includes filesystem-reserved blocks unavailable to the service user.
	d.UsedBytes = total - free
	d.UsedPercent = 100 * float64(d.UsedBytes) / float64(total)
	return d
}

package storage

import "testing"

func TestDiskSpace(t *testing.T) {
	d := DiskSpace(t.TempDir())
	if d.Error != "" {
		t.Fatal(d.Error)
	}
	if d.TotalBytes <= 0 || d.AvailableBytes < 0 || d.UsedBytes+d.AvailableBytes != d.TotalBytes || d.UsedPercent < 0 || d.UsedPercent > 100 {
		t.Fatalf("invalid disk metrics: %+v", d)
	}
	if DiskSpace("/nonexistent-cfc-disk-path").Error == "" {
		t.Fatal("missing filesystem should be unavailable")
	}
}

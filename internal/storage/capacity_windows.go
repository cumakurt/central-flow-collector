//go:build windows

package storage

// Local flow size remains available on Windows even when volume capacity is
// not exposed by the standard library.
func filesystemCapacity(path string) (free, total int64) { return 0, 0 }

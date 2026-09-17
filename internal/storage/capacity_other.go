//go:build !windows && !linux && !darwin

package storage

// Keep collection portable when the target OS does not expose a compatible
// statfs structure through the standard syscall package.
func filesystemCapacity(string) (free, total int64) { return 0, 0 }

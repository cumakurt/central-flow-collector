//go:build linux || darwin

package storage

import "syscall"

func filesystemCapacity(path string) (free, total int64) {
	var st syscall.Statfs_t
	if syscall.Statfs(path, &st) == nil {
		return int64(st.Bavail) * int64(st.Bsize), int64(st.Blocks) * int64(st.Bsize)
	}
	return 0, 0
}

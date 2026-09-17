//go:build linux || darwin

package dr

import (
	"os"
	"syscall"
)

func ownerIDs(st os.FileInfo) (int, int) {
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		return int(sys.Uid), int(sys.Gid)
	}
	return -1, -1
}

//go:build !windows && !linux && !darwin

package dr

import "os"

// Filesystem ownership restoration is best-effort on platforms whose native
// stat structure is not exposed consistently by Go's syscall package.
func ownerIDs(os.FileInfo) (int, int) { return -1, -1 }

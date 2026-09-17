//go:build windows

package dr

import "os"

func ownerIDs(st os.FileInfo) (int, int) { return -1, -1 }

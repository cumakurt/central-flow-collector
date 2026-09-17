//go:build !linux

package collector

import (
	"fmt"
	"net"
)

func listenSCTP(string, int) (net.Listener, error) {
	return nil, fmt.Errorf("sctp transport is only available on linux builds")
}

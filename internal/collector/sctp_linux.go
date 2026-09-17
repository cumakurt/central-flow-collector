//go:build linux

package collector

import (
	"fmt"
	"net"
	"os"
	"syscall"
)

func listenSCTP(bind string, port int) (net.Listener, error) {
	ip := net.ParseIP(bind)
	if ip == nil {
		ip = net.IPv4zero
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("sctp listener requires an IPv4 bind address")
	}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_SCTP)
	if err != nil {
		return nil, fmt.Errorf("sctp socket: %w", err)
	}
	addr := &syscall.SockaddrInet4{Port: port}
	copy(addr.Addr[:], ip4)
	if err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	if err = syscall.Bind(fd, addr); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("sctp bind: %w", err)
	}
	if err = syscall.Listen(fd, 128); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("sctp listen: %w", err)
	}
	f := os.NewFile(uintptr(fd), "flowcollector-sctp")
	ln, err := net.FileListener(f)
	_ = f.Close()
	return ln, err
}

//go:build linux

package collector

import (
	"fmt"
	"net"
	"runtime"
	"sync"
	"syscall"
	"unsafe"
)

type mmsghdr struct {
	Hdr syscall.Msghdr
	Len uint32
	_   uint32
}

type linuxBatchReader struct {
	raw   syscall.RawConn
	batch int
	msgs  []mmsghdr
	iov   []syscall.Iovec
	addrs []syscall.RawSockaddrAny
	bufs  [][]byte
	out   []udpDatagram
}

func newPacketBatchReader(conn *net.UDPConn, batch int) (packetBatchReader, error) {
	if batch < 1 {
		batch = 1
	}
	if batch > 64 {
		batch = 64
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}
	return &linuxBatchReader{raw: raw, batch: batch, msgs: make([]mmsghdr, batch), iov: make([]syscall.Iovec, batch), addrs: make([]syscall.RawSockaddrAny, batch), bufs: make([][]byte, batch), out: make([]udpDatagram, 0, batch)}, nil
}

func sockaddrIP(a *syscall.RawSockaddrAny) string {
	switch a.Addr.Family {
	case syscall.AF_INET:
		x := (*syscall.RawSockaddrInet4)(unsafe.Pointer(a))
		return net.IP(x.Addr[:]).String()
	case syscall.AF_INET6:
		x := (*syscall.RawSockaddrInet6)(unsafe.Pointer(a))
		return net.IP(x.Addr[:]).String()
	}
	return ""
}

func sockaddrPort(a *syscall.RawSockaddrAny) uint16 {
	// Both sockaddr_in and sockaddr_in6 place the network-order port after family.
	bytes := (*[4]byte)(unsafe.Pointer(a))
	return uint16(bytes[2])<<8 | uint16(bytes[3])
}

func (r *linuxBatchReader) Read(pool *sync.Pool) ([]udpDatagram, error) {
	r.out = r.out[:0]
	for i := 0; i < r.batch; i++ {
		b := pool.Get().([]byte)
		if cap(b) < 65535 {
			b = make([]byte, 65535)
		}
		b = b[:cap(b)]
		r.bufs[i] = b
		r.iov[i] = syscall.Iovec{Base: &b[0], Len: uint64(len(b))}
		r.addrs[i] = syscall.RawSockaddrAny{}
		r.msgs[i] = mmsghdr{}
		r.msgs[i].Hdr.Name = (*byte)(unsafe.Pointer(&r.addrs[i]))
		r.msgs[i].Hdr.Namelen = uint32(unsafe.Sizeof(r.addrs[i]))
		r.msgs[i].Hdr.Iov = &r.iov[i]
		r.msgs[i].Hdr.Iovlen = 1
	}
	n := 0
	var sysErr error
	err := r.raw.Read(func(fd uintptr) bool {
		n1, _, errno := syscall.Syscall6(syscall.SYS_RECVMMSG, fd, uintptr(unsafe.Pointer(&r.msgs[0])), uintptr(r.batch), uintptr(syscall.MSG_DONTWAIT), 0, 0)
		if errno == syscall.EAGAIN || errno == syscall.EWOULDBLOCK {
			return false
		}
		if errno != 0 {
			sysErr = errno
			return true
		}
		n = int(n1)
		return true
	})
	if err != nil || sysErr != nil {
		for i := 0; i < r.batch; i++ {
			if r.bufs[i] != nil {
				pool.Put(r.bufs[i])
				r.bufs[i] = nil
			}
		}
		if err != nil {
			return nil, err
		}
		return nil, sysErr
	}
	if n < 1 || n > r.batch {
		for i := 0; i < r.batch; i++ {
			pool.Put(r.bufs[i])
			r.bufs[i] = nil
		}
		return nil, fmt.Errorf("recvmmsg returned invalid batch size %d", n)
	}
	for i := 0; i < n; i++ {
		l := int(r.msgs[i].Len)
		b := r.bufs[i]
		src := sockaddrIP(&r.addrs[i])
		r.bufs[i] = nil
		if l < 0 || l > len(b) || src == "" {
			pool.Put(b)
			continue
		}
		r.out = append(r.out, udpDatagram{data: b, n: l, src: src, port: sockaddrPort(&r.addrs[i])})
	}
	for i := n; i < r.batch; i++ {
		pool.Put(r.bufs[i])
		r.bufs[i] = nil
	}
	runtime.KeepAlive(r.msgs)
	runtime.KeepAlive(r.iov)
	runtime.KeepAlive(r.addrs)
	if len(r.out) == 0 {
		return nil, fmt.Errorf("recvmmsg batch contained no usable datagrams")
	}
	return r.out, nil
}

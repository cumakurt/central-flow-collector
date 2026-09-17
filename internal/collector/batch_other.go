//go:build !linux

package collector

import (
	"net"
	"sync"
	"time"
)

type singleReader struct{ conn *net.UDPConn }

func newPacketBatchReader(conn *net.UDPConn, batch int) (packetBatchReader, error) {
	return &singleReader{conn: conn}, nil
}
func (r *singleReader) Read(pool *sync.Pool) ([]udpDatagram, error) {
	b := pool.Get().([]byte)
	_ = r.conn.SetReadDeadline(time.Now().Add(time.Second))
	n, a, e := r.conn.ReadFromUDP(b)
	if e != nil {
		pool.Put(b)
		return nil, e
	}
	return []udpDatagram{{data: b, n: n, src: a.IP.String(), port: uint16(a.Port)}}, nil
}

//go:build linux

package collector

import (
	"net"
	"sync"
	"testing"
	"time"
)

func TestBatchReaderReceivesUDP(t *testing.T) {
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	r, err := newPacketBatchReader(c, 8)
	if err != nil {
		t.Fatal(err)
	}
	s, err := net.DialUDP("udp", nil, c.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for i := 0; i < 4; i++ {
		if _, err = s.Write([]byte{1, 2, 3, byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	var p sync.Pool
	p.New = func() any { return make([]byte, 65535) }
	done := make(chan []udpDatagram, 1)
	errs := make(chan error, 1)
	go func() {
		x, e := r.Read(&p)
		if e != nil {
			errs <- e
			return
		}
		done <- x
	}()
	select {
	case e := <-errs:
		t.Fatal(e)
	case x := <-done:
		if len(x) < 1 || len(x) > 4 {
			t.Fatalf("batch len=%d", len(x))
		}
		for _, d := range x {
			if d.port != uint16(s.LocalAddr().(*net.UDPAddr).Port) {
				t.Fatalf("source port lost: %d", d.port)
			}
			p.Put(d.data[:cap(d.data)])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("batch read timeout")
	}
}
func TestShardIndexStable(t *testing.T) {
	a := shardIndex("10.0.0.1", 8)
	for i := 0; i < 100; i++ {
		if shardIndex("10.0.0.1", 8) != a {
			t.Fatal("unstable shard")
		}
	}
	if a < 0 || a >= 8 {
		t.Fatal(a)
	}
}

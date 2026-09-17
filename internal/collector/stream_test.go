package collector

import (
	"central-flow-collector/internal/config"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestStreamConnFramesIPFIX(t *testing.T) {
	c := New(config.Default(), nil, nil, nil, nil)
	rt := &listenerRuntime{cfg: config.Listener{Name: "ipfix-tcp", Protocol: "ipfix", Port: 14739}, queues: []chan packet{make(chan packet, 1)}}
	server, client := net.Pipe()
	c.wg.Add(1)
	done := make(chan struct{})
	go func() {
		c.streamConn(rt, server)
		close(done)
	}()
	frame := make([]byte, 16)
	binary.BigEndian.PutUint16(frame[0:2], 10)
	binary.BigEndian.PutUint16(frame[2:4], uint16(len(frame)))
	if _, err := client.Write(frame); err != nil {
		t.Fatal(err)
	}
	select {
	case p := <-rt.queues[0]:
		if len(p.data) != len(frame) || p.ctx.Protocol != "ipfix" {
			t.Fatalf("unexpected stream packet: %+v", p)
		}
	case <-time.After(time.Second):
		t.Fatal("stream frame was not queued")
	}
	_ = client.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stream connection did not close")
	}
}

package collector

import (
	"central-flow-collector/internal/config"
	"testing"
)

func TestAnySourceAdmissionForDatagramsAndStreams(t *testing.T) {
	c := New(config.Default(), nil, nil, nil, nil)
	defer c.cancel()
	rt := &listenerRuntime{cfg: config.Listener{Name: "netflow", Protocol: "netflow", Port: 2055}, queues: []chan packet{make(chan packet, 1)}}
	for _, source := range []string{"192.0.2.4", "198.51.100.7", "2001:db8::7"} {
		b := make([]byte, 24)
		c.dispatchDatagram(rt, udpDatagram{data: b, n: len(b), src: source})
		select {
		case p := <-rt.queues[0]:
			if p.ctx.Exporter != source {
				t.Fatal("wrong source")
			}
		default:
			t.Fatalf("UDP source %s was blocked", source)
		}
		c.dispatchStreamDatagram(rt, b, source, 1234)
		select {
		case <-rt.queues[0]:
		default:
			t.Fatalf("stream source %s was blocked", source)
		}
	}
}

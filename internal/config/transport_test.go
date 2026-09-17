package config

import "testing"

func TestValidateFlowTransports(t *testing.T) {
	c := Default()
	c.Listeners = []Listener{{Name: "ipfix-tcp", Bind: "127.0.0.1", Port: 14739, Protocol: "ipfix", Transport: "tcp", Workers: 1, QueueSize: 64, BatchSize: 1, Enabled: true}}
	if err := Validate(c); err != nil {
		t.Fatalf("tcp listener rejected: %v", err)
	}
	c.Listeners[0].Transport = "sctp"
	if err := Validate(c); err != nil {
		t.Fatalf("sctp listener rejected: %v", err)
	}
	c.Listeners[0].Protocol = "netflow"
	if err := Validate(c); err == nil {
		t.Fatal("expected non-IPFIX stream listener rejection")
	}
}

package audit

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHashChainDetectsTamper(t *testing.T) {
	d := t.TempDir()
	l := New(d)
	l.Write(Event{User: "a", Action: "login", Success: true})
	l.Write(Event{User: "a", Action: "policy", Success: true})
	v := l.Verify()
	if !v.OK || v.Verified != 2 {
		t.Fatalf("verify=%+v", v)
	}
	p := filepath.Join(d, "audit.jsonl")
	b, _ := os.ReadFile(p)
	for i := range b {
		if b[i] == 'p' {
			b[i] = 'q'
			break
		}
	}
	_ = os.WriteFile(p, b, 0640)
	if v = l.Verify(); v.OK {
		t.Fatal("tamper not detected")
	}
}

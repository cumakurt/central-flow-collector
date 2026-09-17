package dedup

import (
	"fmt"
	"testing"
	"time"

	"central-flow-collector/internal/model"
)

func TestDetectorUniqueFlowFloodStaysBounded(t *testing.T) {
	const maxEntries = 1000
	d := New(30*time.Second, maxEntries)
	now := time.Now()
	for i := 0; i < 5000; i++ {
		f := model.Flow{Exporter: "192.0.2.1", Protocol: "netflow5", Sequence: uint32(i + 1), SrcIP: fmt.Sprintf("10.0.%d.%d", (i/250)%250, i%250+1), DstIP: "172.16.0.1", SrcPort: uint16(1000 + i%50000), DstPort: 443, IPProtocol: 6, Bytes: uint64(1000 + i)}
		if !d.Accept(f, now) {
			t.Fatalf("unique flow %d was rejected as duplicate", i)
		}
	}
	st := d.Stats()
	if st.Entries > maxEntries {
		t.Fatalf("entries=%d exceeds max=%d", st.Entries, maxEntries)
	}
	if st.Accepted != 5000 {
		t.Fatalf("accepted=%d, want 5000", st.Accepted)
	}
	if st.Evicted < 4000 {
		t.Fatalf("evicted=%d, want at least 4000", st.Evicted)
	}
}

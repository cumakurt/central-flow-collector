package storage

import (
	"central-flow-collector/internal/model"
	"context"
	"testing"
	"time"
)

func TestLocalAssetsAndConversations(t *testing.T) {
	dir := t.TempDir()
	l, err := NewLocal(dir, 64, 7)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	_ = l.Write(model.Flow{ReceiveTime: now, SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 1111, DstPort: 443, IPProtocol: 6, Bytes: 100, Packets: 1})
	_ = l.Write(model.Flow{ReceiveTime: now.Add(time.Millisecond), SrcIP: "10.0.0.2", DstIP: "10.0.0.1", SrcPort: 443, DstPort: 1111, IPProtocol: 6, Bytes: 50, Packets: 2})
	defer l.Close()
	q := AggregateQuery{From: now.Add(-time.Second), To: now.Add(time.Second), Limit: 10}
	assets, err := l.Assets(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) != 2 {
		t.Fatalf("assets=%+v", assets)
	}
	var a AssetSummary
	for _, x := range assets {
		if x.IP == "10.0.0.1" {
			a = x
		}
	}
	if a.BytesOut != 100 || a.BytesIn != 50 || a.Peers != 1 {
		t.Fatalf("asset=%+v", a)
	}
	conv, err := l.Conversations(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	if len(conv) != 1 || conv[0].BytesAB != 100 || conv[0].BytesBA != 50 {
		t.Fatalf("conv=%+v", conv)
	}
}

package intelligence

import (
	"math"
	"testing"
	"time"
)

func spec(kind string) Spec {
	return Spec{Kind: kind, Dimension: "application", Metric: "bytes", Peer: "dst_ip", Bucket: 3600, Top: 2, Bins: 10, Strategy: "linear", Threshold: 99}
}
func closeTo(t *testing.T, a, b float64) {
	t.Helper()
	if math.Abs(a-b) > 1e-8*max(1, math.Abs(b)) {
		t.Fatalf("got %g want %g", a, b)
	}
}
func TestContributionReconciles(t *testing.T) {
	from := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	groups := []Group{{Key: "A", Period: 0, Bytes: 600e9}, {Key: "A", Period: 1, Bytes: 900e9}, {Key: "B", Period: 0, Bytes: 300e9}, {Key: "B", Period: 1, Bytes: 450e9}, {Key: "C", Period: 0, Bytes: 100e9}, {Key: "C", Period: 1, Bytes: 150e9}}
	r := Calculate(spec("changes"), groups, from, from.Add(time.Hour))
	closeTo(t, r.Summary["delta"], 500e9)
	closeTo(t, r.Rows[0].Delta, 300e9)
	closeTo(t, *r.Rows[0].Contribution, 60)
	sum := r.Summary["other_delta"]
	for _, x := range r.Rows {
		sum += x.Delta
	}
	closeTo(t, sum, 500e9)
	groups = append(groups, Group{Key: "negative", Period: 0, Bytes: 100e9})
	r = Calculate(spec("changes"), groups, from, from.Add(time.Hour))
	closeTo(t, r.Summary["delta"], 400e9)
}
func TestEntropyAndShift(t *testing.T) {
	s := spec("concentration")
	r := Calculate(s, []Group{{Key: "a", Period: 1, Bytes: 1}, {Key: "b", Period: 1, Bytes: 1}}, time.Now(), time.Now())
	closeTo(t, r.Summary["normalized_entropy"], 1)
	closeTo(t, r.Summary["hhi"], .5)
	r = Calculate(s, []Group{{Key: "a", Period: 1, Bytes: 9999}, {Key: "b", Period: 1, Bytes: 1}}, time.Now(), time.Now())
	if r.Summary["normalized_entropy"] > .01 {
		t.Fatal(r.Summary)
	}
	s.Kind = "changes"
	r = Calculate(s, []Group{{Key: "a", Period: 0, Bytes: 1}, {Key: "b", Period: 1, Bytes: 1}}, time.Now(), time.Now())
	closeTo(t, r.Summary["jensen_shannon_bits"], 1)
	if r.Rows[0].Contribution != nil {
		t.Fatal("zero net delta must have undefined contribution")
	}
}
func TestWeightedPercentilesAndHistogram(t *testing.T) {
	var groups []Group
	for i := 1; i <= 100; i++ {
		groups = append(groups, Group{Value: float64(i), Bytes: uint64(i), Packets: 1, Flows: 1, Period: 1})
	}
	s := spec("distribution")
	s.Dimension = "bytes"
	r := Calculate(s, groups, time.Now(), time.Now())
	for k, v := range map[string]float64{"p50": 50, "p95": 95, "p99": 99, "elephant_flow_share": 1} {
		closeTo(t, r.Summary[k], v)
	}
	closeTo(t, r.Summary["elephant_byte_share"], 10000./5050)
	var n uint64
	for _, b := range r.Histogram {
		n += b.Count
	}
	if n != 100 {
		t.Fatal(n)
	}
	closeTo(t, r.Histogram[len(r.Histogram)-1].CDF, 1)
	s.Strategy = "logarithmic"
	r = Calculate(s, []Group{{Value: 0, Flows: 100, Period: 1}}, time.Now(), time.Now())
	if len(r.Histogram) != 1 || r.Histogram[0].Count != 100 {
		t.Fatal(r)
	}
}
func TestRelationshipsAndDiversity(t *testing.T) {
	from := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	gs := []Group{{Key: "a", Peer: "b", Flows: 1, Bytes: 10, Period: 1, Bucket: from.Unix()}, {Key: "a", Peer: "b", Flows: 1, Bytes: 20, Period: 1, Bucket: from.Add(time.Hour).Unix()}, {Key: "a", Peer: "c", Flows: 1, Bytes: 5, Period: 1, Bucket: from.Unix()}}
	r := Calculate(spec("relationships"), gs, from, from.Add(4*time.Hour))
	closeTo(t, r.Rows[0].Recurrence, 50)
	r = Calculate(spec("diversity"), gs, from, from.Add(4*time.Hour))
	closeTo(t, r.Summary["p95"], 2)
	if r.Rows[0].Peers != 2 {
		t.Fatal(r.Rows)
	}
}
func TestTemporalZeroBucketsAndPartialEdges(t *testing.T) {
	from := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	gs := []Group{{Period: 1, Bucket: from.Unix(), Bytes: 3600}}
	r := Calculate(spec("temporal"), gs, from, from.Add(2*time.Hour))
	closeTo(t, r.Summary["average_rate"], 4)
	closeTo(t, r.Summary["peak_to_average"], 2)
	closeTo(t, r.Summary["coefficient_of_variation"], 1)
	r = Calculate(spec("temporal"), gs, from.Add(time.Minute), from.Add(2*time.Hour))
	closeTo(t, r.Summary["average_rate"], 0)
	closeTo(t, r.Summary["complete_buckets"], 1)
}
func TestSamplingAndActivityAreNotCompleteness(t *testing.T) {
	from := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	r := Calculate(spec("quality"), []Group{{Key: "router", Period: 1, Flows: 10, Sampled: 4, SamplingUnknown: 2}}, from, from.Add(4*time.Hour))
	closeTo(t, r.Summary["sampled_records"], 4)
	closeTo(t, r.Rows[0].Recurrence, 25)
	if _, ok := r.Summary["completeness"]; ok {
		t.Fatal("no expected-exporter history")
	}
}

func TestRankPersistence(t *testing.T) {
	from := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	s := spec("persistence")
	r := Calculate(s, []Group{{Key: "a", Period: 1, Bucket: from.Unix(), Bytes: 10}, {Key: "b", Period: 1, Bucket: from.Unix(), Bytes: 5}, {Key: "a", Period: 1, Bucket: from.Add(time.Hour).Unix(), Bytes: 5}, {Key: "b", Period: 1, Bucket: from.Add(time.Hour).Unix(), Bytes: 10}}, from, from.Add(4*time.Hour))
	closeTo(t, r.Rows[0].Top10Presence, 50)
	closeTo(t, r.Rows[0].AverageRank, 1.5)
	closeTo(t, r.Rows[0].RankDeviation, .5)
}

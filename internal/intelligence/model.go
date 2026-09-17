// Package intelligence implements explainable statistics over complete, bounded aggregates.
package intelligence

import (
	"errors"
	"time"
)

const MaxGroups = 20000

var ErrCardinality = errors.New("analysis exceeds 20,000 groups; narrow the time range, add filters or choose a coarser dimension")

type Spec struct {
	EventState  string  `json:"event_state,omitempty"`
	Kind        string  `json:"kind"`
	Dimension   string  `json:"dimension"`
	Metric      string  `json:"metric"`
	Peer        string  `json:"peer"`
	Bucket      int     `json:"bucket_seconds"`
	Top         int     `json:"top"`
	Bins        int     `json:"bins"`
	Strategy    string  `json:"strategy"`
	Threshold   float64 `json:"threshold_percentile"`
	CapacityBPS float64 `json:"capacity_bps,omitempty"`
}

var Dimensions = map[string]string{
	"src_site": "Source network group", "dst_site": "Destination network group",
	"src_ip": "Source IP", "dst_ip": "Destination IP", "src_network": "Source /24 or /64", "dst_network": "Destination /24 or /64",
	"application": "Application", "protocol": "Protocol", "src_as": "Source ASN", "dst_as": "Destination ASN",
	"src_country": "Source country", "dst_country": "Destination country", "exporter": "Exporter", "ingress_if": "Ingress interface", "egress_if": "Egress interface", "dst_port": "Destination port",
}

func (s Spec) Validate() error {
	switch s.EventState {
	case "", "PENDING", "ACTIVE", "RECOVERED":
	default:
		return errors.New("event_state must be PENDING, ACTIVE or RECOVERED")
	}
	if s.CapacityBPS < 0 || s.CapacityBPS > 1e15 || s.CapacityBPS != s.CapacityBPS {
		return errors.New("capacity_bps must be between 0 and 1e15")
	}
	if s.CapacityBPS > 0 && (s.Kind != "temporal" || s.Metric != "bytes") {
		return errors.New("capacity requires temporal byte analysis")
	}
	switch s.Kind {
	case "changes", "concentration", "distribution", "relationships", "diversity", "temporal", "quality", "persistence", "anomalies":
	default:
		return errors.New("unsupported analysis kind")
	}
	if s.Metric != "bytes" && s.Metric != "packets" && s.Metric != "flows" {
		return errors.New("metric must be bytes, packets or flows")
	}
	if s.Kind == "distribution" {
		switch s.Dimension {
		case "bytes", "packets", "duration_ms", "bytes_per_packet":
		default:
			return errors.New("unsupported distribution dimension")
		}
	} else if _, ok := Dimensions[s.Dimension]; !ok {
		return errors.New("unsupported dimension")
	}
	if _, ok := Dimensions[s.Peer]; !ok {
		return errors.New("unsupported peer dimension")
	}
	if s.Top < 1 || s.Top > 100 || s.Bins < 4 || s.Bins > 64 {
		return errors.New("top must be 1..100 and bins 4..64")
	}
	if s.Bucket != 60 && s.Bucket != 300 && s.Bucket != 900 && s.Bucket != 3600 && s.Bucket != 86400 {
		return errors.New("bucket must be 60, 300, 900, 3600 or 86400 seconds")
	}
	if s.Strategy != "linear" && s.Strategy != "logarithmic" {
		return errors.New("strategy must be linear or logarithmic")
	}
	if s.Threshold < 50 || s.Threshold > 99.9 {
		return errors.New("threshold must be 50..99.9")
	}
	return nil
}

// Group contains additive counters, not a sample of raw records.
type Group struct {
	// FractionalWeight is used only by derived comparisons (for example medians).
	FractionalWeight *float64 `json:"-"`
	Key              string   `json:"key"`
	Peer             string   `json:"peer"`
	Period           int      `json:"period"`
	Bucket           int64    `json:"bucket"`
	Value            float64  `json:"value"`
	Bytes            uint64   `json:"bytes"`
	Packets          uint64   `json:"packets"`
	Flows            uint64   `json:"flows"`
	Sampled          uint64   `json:"sampled"`
	SamplingUnknown  uint64   `json:"sampling_unknown"`
	Invalid          uint64   `json:"invalid"`
	First            int64    `json:"first"`
	Last             int64    `json:"last"`
}

func (g Group) Weight(metric string) float64 {
	if g.FractionalWeight != nil {
		return *g.FractionalWeight
	}
	if metric == "flows" {
		return float64(g.Flows)
	}
	if metric == "packets" {
		return float64(g.Packets)
	}
	return float64(g.Bytes)
}

type Row struct {
	Top10Presence float64  `json:"top10_presence_percent,omitempty"`
	Top50Presence float64  `json:"top50_presence_percent,omitempty"`
	AverageRank   float64  `json:"average_rank,omitempty"`
	RankDeviation float64  `json:"rank_standard_deviation,omitempty"`
	Key           string   `json:"key"`
	Peer          string   `json:"peer,omitempty"`
	Current       float64  `json:"current"`
	Previous      float64  `json:"previous"`
	Delta         float64  `json:"delta"`
	Contribution  *float64 `json:"contribution_percent"`
	Share         float64  `json:"share_percent"`
	ShareDelta    float64  `json:"share_delta_pp"`
	Rank          int      `json:"rank"`
	PreviousRank  int      `json:"previous_rank"`
	Status        string   `json:"status,omitempty"`
	Peers         int      `json:"peers,omitempty"`
	Active        int      `json:"active_buckets,omitempty"`
	Recurrence    float64  `json:"recurrence_percent,omitempty"`
	Flows         uint64   `json:"flows"`
	Bytes         uint64   `json:"bytes"`
	First         int64    `json:"first,omitempty"`
	Last          int64    `json:"last,omitempty"`
}
type Point struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
}
type Bin struct {
	From  float64 `json:"from"`
	To    float64 `json:"to"`
	Count uint64  `json:"count"`
	CDF   float64 `json:"cdf"`
}
type Result struct {
	Anomalies *AnomalyAnalysis   `json:"anomalies,omitempty"`
	Spec      Spec               `json:"spec"`
	From      time.Time          `json:"from"`
	To        time.Time          `json:"to"`
	Generated time.Time          `json:"generated_at"`
	Source    string             `json:"source"`
	Method    string             `json:"method"`
	Notes     []string           `json:"notes"`
	Groups    int                `json:"groups"`
	Summary   map[string]float64 `json:"summary"`
	Rows      []Row              `json:"rows"`
	Curve     []Point            `json:"curve"`
	Histogram []Bin              `json:"histogram"`
}

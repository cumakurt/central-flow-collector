package intelligence

import (
	"math"
	"sort"
)

func persistence(r *Result, groups []Group) {
	buckets := map[int64][]Group{}
	for _, g := range groups {
		if g.Weight(r.Spec.Metric) > 0 {
			buckets[g.Bucket] = append(buckets[g.Bucket], g)
		}
	}
	type state struct {
		row                  Row
		rankSum, rankSquares float64
		top10, top50         int
	}
	entities := map[string]*state{}
	for _, gs := range buckets {
		sort.Slice(gs, func(i, j int) bool {
			if gs[i].Weight(r.Spec.Metric) == gs[j].Weight(r.Spec.Metric) {
				return gs[i].Key < gs[j].Key
			}
			return gs[i].Weight(r.Spec.Metric) > gs[j].Weight(r.Spec.Metric)
		})
		for i, g := range gs {
			x := entities[g.Key]
			if x == nil {
				x = &state{row: Row{Key: g.Key}}
				entities[g.Key] = x
			}
			rank := float64(i + 1)
			x.rankSum += rank
			x.rankSquares += rank * rank
			x.row.Active++
			x.row.Bytes += g.Bytes
			x.row.Flows += g.Flows
			x.row.Current += g.Weight(r.Spec.Metric)
			if i < 10 {
				x.top10++
			}
			if i < 50 {
				x.top50++
			}
		}
	}
	n := math.Ceil(float64(r.To.UnixMilli())/float64(r.Spec.Bucket*1000)) - math.Floor(float64(r.From.UnixMilli())/float64(r.Spec.Bucket*1000))
	for _, x := range entities {
		x.row.Top10Presence = 100 * ratio(float64(x.top10), n)
		x.row.Top50Presence = 100 * ratio(float64(x.top50), n)
		x.row.AverageRank = ratio(x.rankSum, float64(x.row.Active))
		x.row.RankDeviation = math.Sqrt(max(0, ratio(x.rankSquares, float64(x.row.Active))-x.row.AverageRank*x.row.AverageRank))
		r.Rows = append(r.Rows, x.row)
	}
	sort.Slice(r.Rows, func(i, j int) bool {
		if r.Rows[i].Top10Presence == r.Rows[j].Top10Presence {
			if r.Rows[i].AverageRank == r.Rows[j].AverageRank {
				return r.Rows[i].Key < r.Rows[j].Key
			}
			return r.Rows[i].AverageRank < r.Rows[j].AverageRank
		}
		return r.Rows[i].Top10Presence > r.Rows[j].Top10Presence
	})
	r.Summary["entities"] = float64(len(entities))
	r.Summary["window_buckets"] = n
	r.Rows = r.Rows[:min(len(r.Rows), r.Spec.Top)]
	r.Method = "Rank each positive-weight entity within each UTC interval; ties use ascending key. Top-10/50 presence divides by all intersecting window buckets. Average rank and population rank deviation use only active buckets. Gaps and partial edge buckets are included in presence denominator."
}

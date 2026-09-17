package notification

import (
	"context"
	"errors"
	"time"

	"central-flow-collector/internal/intelligence"
)

// EvaluateSeasonal reuses the ordinary filtered/grouped aggregate evaluator.
// Five disjoint one-hour queries replace a full month scan. There is no
// ingestion callback, timer per entity, or independent notification scheduler.
func EvaluateSeasonal(ctx context.Context, r RuleDefinition, at time.Time, aggregate Evaluator) ([]Observation, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	if r.Kind != "seasonal" {
		return nil, errors.New("seasonal rule required")
	}
	// Leave a one-minute grace period for late records and exclude partial hours.
	end := at.Add(-time.Minute).UTC().Truncate(time.Hour)
	query := r
	query.Kind = "aggregate"
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	current, err := aggregate(ctx, query, end)
	if err != nil {
		return nil, err
	}
	if len(current) > MaxGroups {
		return nil, errors.New("seasonal group limit exceeded")
	}
	history := make(map[string][]float64, len(current))
	valid := make(map[string]bool, len(current))
	for _, o := range current {
		valid[o.Entity] = o.Records > 0 && o.SamplingUnavailable == 0
	}
	for week := 1; week <= 4; week++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		rows, err := aggregate(ctx, query, end.AddDate(0, 0, -7*week))
		if err != nil {
			return nil, err
		}
		if len(rows) > MaxGroups {
			return nil, errors.New("seasonal history group limit exceeded")
		}
		for _, o := range rows {
			if _, tracked := valid[o.Entity]; !tracked {
				continue
			}
			if o.SamplingUnavailable > 0 {
				valid[o.Entity] = false
			}
			if o.Records > 0 {
				history[o.Entity] = append(history[o.Entity], o.Value)
			}
		}
	}
	out := []Observation{}
	for _, o := range current {
		if !valid[o.Entity] || len(history[o.Entity]) < 3 {
			continue
		}
		b := intelligence.SeasonalBounds(history[o.Entity], r.Threshold, r.MinimumCurrent)
		b.WindowEnd = end
		o.Baseline = &b
		out = append(out, o)
	}
	// An empty successful evaluation must not imply normality. applyEvaluation
	// deliberately leaves missing seasonal groups unchanged.
	return out, nil
}

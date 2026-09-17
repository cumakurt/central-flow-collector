package storage

import (
	"central-flow-collector/internal/engineering"
	"context"
	"errors"
	"time"
)

type EngineeringBackend interface {
	EngineeringSummary(context.Context, time.Time, time.Time, *engineering.RouteProvider) (engineering.EngineeringSummary, error)
}

func validateEngineeringRange(from, to time.Time) error {
	if from.IsZero() || to.IsZero() || !to.After(from) {
		return errors.New("engineering analytics requires a positive time range")
	}
	if to.Sub(from) > 31*24*time.Hour {
		return errors.New("engineering analytics range is limited to 31 days")
	}
	return nil
}
func (l *Local) EngineeringSummary(ctx context.Context, from, to time.Time, p *engineering.RouteProvider) (engineering.EngineeringSummary, error) {
	if e := validateEngineeringRange(from, to); e != nil {
		return engineering.EngineeringSummary{}, e
	}
	rows, e := l.Query(ctx, Query{From: from, To: to, Limit: engineering.MaxRows})
	if e != nil {
		return engineering.EngineeringSummary{}, e
	}
	return engineering.Summarize(ctx, rows, from, to, p)
}
func (c *ClickHouse) EngineeringSummary(ctx context.Context, from, to time.Time, p *engineering.RouteProvider) (engineering.EngineeringSummary, error) {
	if e := validateEngineeringRange(from, to); e != nil {
		return engineering.EngineeringSummary{}, e
	}
	rows, e := c.Query(ctx, Query{From: from, To: to, Limit: engineering.MaxRows})
	if e != nil {
		return engineering.EngineeringSummary{}, e
	}
	return engineering.Summarize(ctx, rows, from, to, p)
}

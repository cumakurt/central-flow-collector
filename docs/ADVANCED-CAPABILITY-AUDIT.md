# Advanced analytics capability audit

Audit before implementation, 2026-09-15. The pending Flow Explorer export fix is preserved.

## Existing / partial / missing

- Collection, enrichment, deduplication: EXISTS. `collector`, `decoder`, `enrichment`, `dedup`, cluster dedup; unit and race coverage. Live state has configured bounds. Do not add a competing deduplicator.
- Overview, Top-N, time series, filters: EXISTS. `storage/analytics.go`, `/analytics`, `app.js`. Local historical aggregation uses uncapped maps; ClickHouse performs multiple queries. New primitives must not inherit that memory pattern.
- Change explanation, share/rank change, lifecycle: PARTIAL. `/analytics/compare`, `insights.js`, `insight-state.js` compare Top-50 lists. Missing entities cannot safely be treated as zero. No reconciled server-side contribution table or distribution distance.
- Bandwidth percentiles: EXISTS/PARTIAL. `bandwidthPage`, `rateSummary`; nearest-rank median/P95 on complete buckets. Missing server-side burstiness and broader percentiles. Zero buckets mean no records, not verified exporter availability.
- Baseline: EXISTS/PARTIAL. Bounded host/hour-of-week mean, variance, EWMA, persistence and tests. Not a median/MAD historical profile.
- Endpoints, peers, conversations: EXISTS/PARTIAL. Filtered aggregation, bidirectional totals, first/last seen, exact peer counts, API tests. Missing recurrence, fan-in/out population percentiles and relationship activity history.
- Traffic matrix: EXISTS/PARTIAL. IPv4 /24 and IPv6 /64 relationships. Missing ASN/country relationship axes and recurrence.
- Concentration, entropy, Lorenz, distribution distance: MISSING backend/UI/tests.
- Flow-size/duration/packet distribution, CDF, weighted percentiles: MISSING backend/UI/tests.
- Capacity/storage: PARTIAL. Disk capacity, retention, estimated daily growth; bandwidth view. No configured interface capacities or robust forecasting history.
- Telemetry quality: PARTIAL. Exporter decode/template/sequence counters, silence health; no historical expected-exporter inventory. Historical completeness cannot be inferred from lifetime counters.
- Reporting: EXISTS. PDF/XLSX/CSV/JSON, saved reports. New exports must carry method/time/filter/sampling metadata.
- Saved views: EXISTS. Filters, columns, sort, visualization, time configuration. Advanced parameters need explicit preservation.
- Rollups: PARTIAL. Five-minute SummingMergeTree exists, but current Analyze reads raw. Country columns are absent from the sorting key although grouped by the materialized view: unsafe to claim country rollup equivalence. No safe size-percentile reconstruction from totals.
- Caching: PARTIAL. Short-lived browser resource cache. No analytical server cache. Do not add cache state without measured need.
- Benchmarks: EXISTS/PARTIAL. Local querybench 50K default, p50/p95, mostly Analyze. Missing advanced operations, p99, deterministic heavy-tail fixtures.

## Architecture decision

Use a bounded server-side grouped primitive shared by Local and ClickHouse. Keep statistical transforms independent of HTTP/storage. Use exact groups or fail explicitly at the cardinality ceiling, never calculate population metrics from a truncated Top-N. Select one dimension per contribution analysis: contributions from different dimensions overlap and must never be added together. Use raw records for metrics that the existing rollup cannot reconstruct. No schema migration is needed for this increment.

Per-request maps expire at request completion; no persistent analytical cache. Bound grouped rows, raw range, concurrent requests, ClickHouse group memory and returned rows. Preserve cancellation and existing RBAC. Expose observed counters and sampling coverage without inventing normalized values or historical availability.

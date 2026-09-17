# Advanced network usage intelligence

## Existing capabilities reused

The [capability audit](ADVANCED-CAPABILITY-AUDIT.md) records the pre-change inventory. Collection, decoders, enrichment, deduplication, Overview, IP Detail, Flow Explorer, reporting and the existing seasonal EWMA are retained. Existing Sites/CIDR definitions supply named network cohorts; no second group-management system is introduced.

## Analytical primitive

`GET /api/v1/analytics/query` accepts the existing flow filters and these structured parameters:

- `kind`: changes, concentration, distribution, relationships, diversity, temporal, quality, persistence.
- `dimension`, `peer`: allowlisted source/destination IP, network (/24 IPv4, /64 IPv6), site, ASN, country; application, protocol, exporter, ingress/egress interface, destination port. Interface identity includes exporter to avoid mixing identical ifIndex values from different routers.
- Distribution dimensions: bytes, packets, duration_ms, bytes_per_packet.
- `metric=bytes|packets|flows`, `top=1..100`, `bucket=60|300|900|3600|86400` seconds.
- `bins=4..64`, `strategy=linear|logarithmic`, `threshold=50..99.9` (percentile).
- Temporal byte queries can supply `capacity_bps=0..1e15`; zero means unconfigured.
- `from`, `to`: RFC3339; default last 24 hours, at most 31 days per selected period. Changes also scan the immediately preceding equal-length period. All new windows use `[from,to)` to avoid double-counting comparison boundaries.
- `format=csv|json` creates a download. Omitting format returns JSON to the workspace.

`src_country`, `dst_country`, `src_site`, `dst_site` are new exact directional filters. They work in Flow Explorer, exports and both storage backends as well as advanced analysis. Existing either-endpoint country/site predicates remain available.

Examples:

```text
/api/v1/analytics/query?kind=changes&dimension=src_site&metric=bytes
/api/v1/analytics/query?kind=distribution&dimension=bytes&threshold=99&strategy=logarithmic
/api/v1/analytics/query?kind=relationships&dimension=src_as&peer=dst_as&bucket=86400
/api/v1/analytics/query?kind=diversity&dimension=src_ip&peer=dst_ip
/api/v1/analytics/query?kind=persistence&dimension=src_network&bucket=86400
/api/v1/analytics/query?kind=temporal&exporter=192.0.2.1&ingress_if=17&capacity_bps=10000000000
```

## Mathematical definitions

### Changes, concentration and distribution shift

For one exclusive categorical dimension, compute complete current and previous weights before ranking. A missing entity is zero only because the entire population was aggregated successfully. Entity delta is `current - previous`. Contribution is `100 * entity_delta / net_delta`; it is null when net change is zero and can be negative or exceed 100% when increases offset decreases. The displayed delta sum plus `other_delta` reconciles to the period delta. Different dimensions overlap and must never be added together.

Shares use full-period totals, not the displayed Top-N. Share change is current minus previous share in **percentage points**. Ranks sort by weight descending, key ascending on ties; zero-weight ranks are absent. `new_in_window` and `inactive_in_window` describe only the two queried windows, not lifetime discovery.

With positive weights `p_i = weight_i / total`, Shannon entropy is `-sum(p_i log2 p_i)`, normalized by `log2(N)` for N > 1, otherwise zero. HHI is `sum(p_i²)` in [0,1]. Top 1/5/10/20% shares use `ceil(N*fraction)` entities. Zero-weight entities do not enter N. Lorenz points accumulate ascending entity weights; display is bounded to about 100 points and population metrics remain exact.

Jensen–Shannon divergence uses base-2 logs and equal weighting: `0.5 KL(P||M) + 0.5 KL(Q||M)`, `M=(P+Q)/2`. Range [0,1]; omitted if either period has zero total. No significance or security verdict is inferred.

### Flow distributions

Group complete numeric values and use their record counts as weights. Nearest-rank percentile is the smallest value whose cumulative count reaches `ceil(p*N)`. P50/P75/P90/P95/P99/P99.9 are returned. Linear histogram edges span the observed min/max; logarithmic edges use log1p/expm1, retaining zero values. All bins are left-inclusive/right-exclusive except the last, which includes the maximum. CDF is cumulative record count/N.

Duration uses exporter end minus start in milliseconds. Missing or reversed timestamps are excluded and counted as invalid; valid zero durations remain. Bytes per packet excludes zero-packet records. Flow populations count exported records; active-timeout segments are not reconstructed sessions. “Elephant” records are strictly greater than the configurable percentile threshold; ties can produce less than the nominal top fraction. Actual record/byte/packet shares are returned. Numeric statistical transforms use float64; counters are uint64 and values above 2^53 can lose unit precision during statistical transformation.

### Relationships, diversity and persistence

Directed key/peer/UTC-bucket groups establish observed relationships. First/last times are reception times. Recurrence = occupied buckets/all buckets intersecting the selected window, including partial edge buckets. This measures observed activity, not data completeness or application architecture. Named sites reuse enrichment assigned at ingestion; changing a CIDR definition does not relabel historical records.

Diversity counts distinct selected peers per selected entity before calculating nearest-rank population percentiles. Selecting source IP → destination IP yields fan-out; reversing dimensions yields fan-in. Scatter plots show a bounded ranking, while percentiles use the complete successfully aggregated population.

Persistence ranks positive-weight entities independently per bucket, ties by ascending key. Top-10/50 presence divides appearances by all intersecting window buckets. Average rank and population standard deviation of rank include active buckets only. Absent intervals affect presence, not an invented last-place rank.

### Capacity Lens

Rate samples use complete UTC buckets only. Empty buckets contain zero observed counters. Bit/s = bytes*8/bucket_seconds; packets/s and flows/s use corresponding counters/bucket_seconds. Population coefficient of variation = standard deviation/mean. Peak-to-average = maximum bucket rate/mean. Zero mean returns zero ratios. These are bucket averages, not instantaneous peaks or billing measurements.

Optional capacity is an operator-supplied assumption stored in the view, not discovered metadata. P95 utilization = 100*P95/capacity; headroom = 100 - utilization and may be negative. A forecast needs at least seven complete UTC days and sub-day buckets. It fits ordinary least squares to each day's nearest-rank P95. Returned values include slope in bit/s/day, R² and a 30-day projection beyond the last complete day. Estimated days to capacity are reported only for a positive slope; they are zero if the fitted current level exceeds capacity. R² is fit quality, not confidence or proof of adequate telemetry. Missing exporters can bias a forecast.

### Telemetry Quality and sampling

Reports exporter activity, first/last reception, sampled-record count (reported rate > 1) and unknown-sampling count (rate 0). Observed counters are never multiplied by sampling rate: protocol-specific extrapolation semantics are not established. Exporter activity coverage is not completeness. Expected inventory history, missing-exporter denominators and historical sequence/decode counters do not exist, so no completeness percentage, quality score or normalized traffic estimate is fabricated.

## Query safety and storage design

Local streams JSONL records; only grouped state is retained. ClickHouse performs grouped aggregation in the database. Each request permits at most 20,000 aggregate groups, labels up to 512 bytes and 2,000 time buckets. Overflow fails the entire analysis with an actionable error, never a plausible statistic over a truncated population. At most two advanced queries run per API server. There is no persistent state/cache to grow or evict; request maps expire on completion. Result tables are capped at 100 rows; histogram 64 bins; timelines 2,000 points.

ClickHouse receives allowlisted expressions and parameterized flow predicates. It uses throw-on-overflow, 256 MiB query memory, two threads and at most 20 seconds; HTTP context allows 25 seconds. ClickHouse resource bounds apply per server and can overshoot at block boundaries: see [query complexity restrictions](https://clickhouse.com/docs/operations/settings/query-complexity). No arbitrary SQL, silent sampling or approximate grouping is accepted.

No schema changes were made. Existing five-minute rollups cannot reconstruct numeric distributions, metadata, recurrence or all predicates; these primitives explicitly use raw data. The existing country rollup sorting-key issue also prevents claiming general raw/rollup equivalence. There is no newly claimed adaptive rollup planner or cache speedup.

Low-cardinality Prometheus counters report advanced queries, failures, cancellations, rejected requests and active concurrency. Per-response duration is wall time; it is not a claimed database scan count. Browser navigation/filter changes cancel obsolete requests. Exact remote ClickHouse cancellation latency is server-dependent and its execution timeout remains the fallback.

## UI and exports

Analytics contains Workspace, What Changed?, Distribution Lab and Capacity Lens. Distribution Lab switches among numeric distribution, concentration and diversity. Traffic Relationships switches between pairs and persistence. Exporters contains health and Telemetry Quality. No new sidebar category is needed.

Analysis links pin exact time bounds. Existing Saved Views persist advanced filters, dimensions, metric, bucket, top, percentile threshold and capacity assumption. JSON and long-form CSV contain time bounds, filters, generation time, method, source, sampling counts, summaries and results. CSV cells neutralize spreadsheet formula prefixes. Existing PDF/XLSX reporting stays unchanged; the new sections are not yet part of PDF/XLSX report composition.

## Explicit next-stage limitations

This is an implemented advanced-analysis increment, not completion of the entire proposed roadmap. Missing capabilities include returning-entity history beyond two windows, median/MAD seasonal profiles, change-point detection, affinity scores, service dependency inference, stored interface capacity inventory, historical exporter completeness, sampling normalization, storage-retention simulations, historical rollup hierarchy, adaptive query planner, query cache, heavy-hitter approximation, long-range calendar/heatmaps and report section composition. These need additional persisted metadata, statistically justified semantics and/or measured database migrations. They have no placeholder UI.

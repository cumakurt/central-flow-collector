# Analytical views

The portal keeps its existing vanilla JavaScript frontend and API routes. Four focused views extend the Analytics and Traffic menus. All use real storage aggregates, the global time selector, editable Flow Lens conditions, and bookmarkable URL state.

## Analytics → Traffic changes

Compare bytes, packets or flow counts across equal adjacent periods, then identify the dimensions contributing the largest absolute change. Dimensions include addresses, applications, protocols, countries, ASNs, exporters, interfaces, direction and ports. Changes use neutral styling; increasing traffic does not automatically mean a positive or negative outcome.

The two periods arrive in one `/analytics/compare?top=50` response. Changing dimension or metric redraws that response without another request. Each dimension is ranked by bytes independently in each period. If an entry is missing from a full Top-50 list, its value is unknown and the UI does not invent a zero or percentage. A shorter list is complete, allowing an absent entry to be treated as zero. A zero previous total has no percentage baseline.

The contributor ledger is the primary view; a compact period overlay provides time context. Address selections open IP Detail; supported category selections open Flow Explorer. Unsupported predicates, such as exporter-reported direction, remain noninteractive.

Example: `/?page=changes&dimension=application&metric=bytes&range=24h`

## Analytics → Bandwidth

The page shows average rate, P95 rate, peak interval rate, a timeline, a ten-bin rate distribution and the ten busiest complete intervals.

- Average rate: selected total bytes × 8 / selected duration in seconds.
- Bucket rate: bytes × 8 / bucket duration in seconds, using the API's adaptive interval.
- P95: nearest-rank percentile of complete bucket rates. Missing buckets count as zero observed traffic. Partial boundary buckets are excluded. A range without a complete interval shows an unavailable percentile, not zero.
- Peak: largest complete bucket average, not an instantaneous rate.
- Busiest-interval drill-down: selects that exact interval in Flow Explorer, preserving other filters. The end excludes the following bucket by one millisecond, consistent with storage timestamp precision and inclusive API bounds.

These statistics describe received telemetry. Missing flows can also represent a collection gap. P95 is an operational measurement, not a contractual billing statistic. No link utilization is inferred without interface capacity data.

Example: `/?page=bandwidth&range=7d&exporter=192.0.2.10`

## Traffic → Endpoints

Rank IPs on the server by total bytes, packets, flows or unique peers. Choose the top 25, 50 or 100, inspect sent/received totals, and open a profile or matching flows. The visible ranking can be downloaded as CSV; it does not export the entire underlying dataset. The export includes raw aggregate fields, including first/last seen and protocols.

Endpoint totals count each endpoint's participation. Summing endpoint traffic double-counts traffic between two listed endpoints. Peer counts reflect only matching flows. The view labels a full ranking as potentially truncated, rather than claiming it is a complete inventory.

Example: `/?page=endpoints&metric=peers&limit=50&range=24h&ip_protocol=TCP`

## Traffic → Conversations

Rank canonical address/port pairs by bytes, packets or flows. Each row shows both directions, combined totals, protocol and last seen. A/B labels are deterministic identities, not client/server roles. Directional drill-down sets both addresses, both ports and protocol; existing conditions remain in force and can yield an empty reverse direction. Port 0 has no exact predicate in the current flow query API, so those direction buttons are disabled; IP profiles remain available.

Example: `/?page=conversations&metric=bytes&limit=100&range=1h&dst_port=443`

## Shared behavior and limits

- Global time and Flow Lens conditions propagate between these views. Selecting an IP profile replaces an existing **Either IP** condition with the selected IP and preserves other conditions. This keeps profile totals, its breakdowns and its URL consistent.
- Ranking limits, metric and dimension are restored on reload. Existing Flow Explorer Saved Views remain available for detailed flow searches.
- Assets, conversations and IP detail accept at most 31 days. Comparisons and bandwidth use the existing analytics range limit and adaptive buckets.
- Local storage scans matching date files and aggregates on the server. ClickHouse applies parameterized predicates to every aggregate subquery. Duration filters are now also applied by the shared ClickHouse analytics predicate builder.
- Requests use the existing route cancellation and timeout behavior. No new periodic poller, runtime dependency or database migration is added. DOM rows are bounded to 100 endpoint/conversation rows, 100 unioned comparison rows and 10 peak intervals. Timelines use one SVG path per series and at most 10,000 intervals.
- Dense tables have sticky headers, keyboard-accessible drill-down controls and horizontally contained scrolling. Both themes use the existing design tokens.
- Overview, Executive, Analytics, Traffic and IP Detail timelines also fill missing aggregate buckets. Sparse samples no longer create a misleading sloping line through hours without received traffic. A completely empty period retains its no-data state.

## Verification

Pure calculations: `node scripts/ui/insight-state.test.cjs`.

Backend behavior: `go test ./internal/storage ./internal/api`; new regression tests cover server ranking before limits, shared filters, bidirectional totals, duration predicates, cancellation, invalid input, HTTP integration and ClickHouse parameterization.

Browser checks: `scripts/ui/insights-interactions.cjs`, with `PLAYWRIGHT_MODULE`, `CHROMIUM_PATH`, `CFC_REVIEW_URL`, and `CFC_REVIEW_CREDENTIAL_FILE` for an isolated collector. The script requires real ingested flow records, including at least one completed timeline bucket. `scripts/ui/seed-lab.cjs` feeds real NetFlow v5 datagrams to a local test collector without intercepting API responses.

Visual checks: `scripts/ui/capture.cjs` supports `CFC_REVIEW_ROUTES=changes,bandwidth,endpoints,conversations`. It captures dark/light screens at 2560×1440, 1920×1080, 1440×900 and 1366×768 and records geometry, API responses and browser errors. Omit the route override to check the existing portal screens as well.

Pixel comparison: `node scripts/ui/compare-screens.cjs BEFORE AFTER OUTPUT` compares matching viewport crops and writes difference images plus JSON measurements. Live timestamps and moving time windows also change pixels; the output needs visual review rather than a zero-difference assertion.

The interaction script can capture the developer/license dialog with `CFC_ABOUT_SCREENS=/tmp/cfc-about-screens`. Project identity and AGPL-3.0-only notices are accessible from the login screen, sidebar footer and System tabs.

# Traffic anomaly analytics

## Capability audit

- Seasonal source-host baseline exists in `internal/analytics/v15.go`: hour-of-week mean, variance and EWMA, bounded host admission, persisted state, one-sided byte alerts. It runs during ingestion and is retained for compatibility.
- Complete-population changes, reconciled contributions, JSD, entropy/HHI, flow-size percentiles, peer diversity, relationships, persistence and burstiness exist in `internal/intelligence`. These are reused rather than duplicated.
- Storage already performs bounded local scans or ClickHouse aggregation with cancellation, 20,000-group limits, 256 MiB query memory and two query threads. Existing five-minute rollups lack sampling provenance; using them for confidence-aware anomalies would silently discard necessary information.
- API query validation, flow filters, RBAC, CSV/JSON export, URL state and saved analysis views already exist. Notifications have an independent durable rule lifecycle and delivery engine.
- Missing: median/MAD seasonal deviation analysis, explicit insufficient-history and sampling gates, expected bounds, reconstructed deviation episodes, and a dedicated explanation workspace.

## Semantics

The anomaly analysis uses complete UTC intervals within the requested history range (maximum 31 days). The last 24 hours are evaluated against earlier matching UTC weekday and interval-of-day slots. At least three earlier comparable observations are required. Missing entity intervals are unavailable, not verified zeros. This is a retrospective analysis; it does not establish that an exporter was healthy during an empty interval.

Expected value is the median. MAD is the median of absolute distances from the median; robust scale is 1.4826 × MAD. Entry requires |delta| > 4 × scale, at least 25% relative change and a metric-specific absolute floor. Zero MAD uses the relative and absolute floors directly. Recovery uses half the entry envelope. Two consecutive complete intervals are needed for ACTIVE; gaps terminate continuity without asserting recovery.

Sampled or unknown-sampling populations are withheld from automatic deviation classification. This conservative gate avoids treating a sampling change as an observed traffic anomaly. Results report counts and reasons rather than a fabricated coverage percentage.

Contributions compare one dimension at a time. Expected network traffic is explicitly the sum of eligible entity medians, not the median of network totals. Top contributors plus Other reconcile to the eligible observed-minus-expected delta. Distribution comparisons use this same eligible population and the existing base-2 JSD implementation. They describe composition differences, not causality.

## Operational limits

This analysis extends the existing query workspace. Retrospective states are separate from persisted alert instances. A 31-day history permits only three or four weekly comparisons; results report limited history rather than high confidence. Historical exporter completeness, sampling-normalized estimates, arbitrary-timezone seasonality and longer-history rollups require additional telemetry/state integration.

## Scheduled rules and notifications

The `seasonal` rule kind extends the existing notification scheduler and durable lifecycle. It supports the existing boolean condition tree, up to three grouping dimensions and 1,000 groups. Metrics include bytes, packets, flows, rates and exact unique sources/destinations (therefore scoped fan-in/fan-out). No additional ingestion callback or independent scheduler is created.

Evaluation runs hourly and queries five disjoint one-hour windows: current and the same UTC hour in the preceding four weeks. A one-minute grace period excludes incomplete/recently closed hours. Existing cancellation, a shared 20-second scheduler deadline, 128 MiB ClickHouse limits and two query threads apply. Sampling metadata is retained by aggregate queries; any sampled/unknown sampling period withholds classification for that group. This path intentionally uses raw data because existing rollups cannot preserve the required sampling/unique-count semantics.

The firing threshold is a configurable robust-scale multiplier (2..10, default 4). `minimum_current` is the minimum absolute deviation for seasonal rules; the relative floor is 25%. The default recovery multiplier is 2 and minimum pending duration is one hour. Missing groups do not recover, missing hours break pending continuity, and repeated evaluation of the same completed hour cannot advance state. Existing cooldown, policies, escalation, silences, encrypted channels, retries and retention apply.

The editable **Seasonal Traffic Deviation** template is disabled until explicitly saved/enabled. Its simulation uses the production evaluator and lifecycle. The shared HTML, plain-text and Telegram renderer includes expected values, dynamic entry bounds, comparable history and limited confidence. Flow Explorer links carry the measured interval and existing supported filter dimensions. Simulation is isolated from live state and never sends messages.

Health/Prometheus expose `cfc_anomaly_evaluations_total`, `cfc_anomaly_evaluations_withheld_total`, and `cfc_anomaly_evaluation_errors_total` without entity labels. Enabling a rule authorizes scheduling; opening the analytical workspace does not create rules or send notifications.

## Current detector coverage

Volume/rate/unique-count seasonal rules and retrospective volume episodes are implemented. JSD, entropy, contribution analysis, peer distribution and relationships reuse the existing intelligence workspaces. Independent scheduled distribution-shift, new-relationship, flow-size-shift and burstiness detectors are not yet implemented. Persistent-level labeling means consecutive seasonal deviations, not a CUSUM or fitted regime-change algorithm. No causality or security verdict is inferred.

## Validation — 2026-09-16

- `go test ./...`, `go vet ./...`, and race tests for intelligence, notifications, storage and API passed. Deterministic tests cover median/MAD, fractional count medians, contribution reconciliation, rises/drops, recovery, missing intervals, sampling changes, repeated evaluations, restart persistence and isolated simulation.
- Local/ClickHouse parity passed for the intelligence analyses and seasonal bytes, packets, flows, bandwidth and unique-destination rules against an isolated ClickHouse instance. No production database was changed.
- JavaScript syntax checks and all 15 analytical state tests passed. Browser checks used real localhost APIs: history selection, state filtering, CSV metadata, seasonal template validation and production Email/Telegram preview rendering. No messages were sent externally.
- Forty screenshots cover Analytics, Change Explorer, Traffic Anomalies, System and Notifications in both themes at 1366×768, 1440×900, 1920×1080 and 2560×1440. No horizontal overflow or browser errors were recorded. Sixteen existing-screen viewport comparisons had at most 2.70% changed pixels; full-page heights changed with historical-data availability and compact empty states, so this is a reviewed comparison rather than a pixel-identical assertion.
- NetFlow v5/v9, IPFIX and sFlow decoder fuzz runs passed. An initial two-second IPFIX fuzz run ended at its deadline; a five-second single-worker repeat passed 373,743 executions without a failing input.
- A 50,000-record local query benchmark measured anomaly p50 189.9 ms and p95/p99 255.3 ms over three iterations. The benchmark fixture contains seven days, so this measures the explicit insufficient-history path, not successful seasonal detection. Separate deterministic fixtures exercise four comparable weeks.
- The 20,000-aggregate/1,000-entity statistical benchmark measured 13.3–20.1 ms/op across runs and 11.6 MB/op. The 1,000-group seasonal rule benchmark measured approximately 0.95–0.96 ms/op and 483 KB/op, excluding database and network time. These are development-machine measurements, not deployment performance guarantees. Million/billion-record database load and long-duration operational tests were not run.

Seasonal layout-only preview returns HTTP 422 until simulation supplies measured bounds. Simulation previews use the same renderer and exact measured interval as real delivery. Existing nonseasonal layout previews remain available.

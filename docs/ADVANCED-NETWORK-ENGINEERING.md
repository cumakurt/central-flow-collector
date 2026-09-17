# Advanced Network Engineering Analytics

## Capability audit

| Capability | Before | Backend / decoder state | This release |
| --- | --- | --- | --- |
| DSCP / ToS | Partial | DSCP was decoded, but field presence was ambiguous | Native presence provenance, classes, coverage and QoS workspace |
| NAT | Partial | Native NAT IP/port fields and ClickHouse columns existed | Explicit pre/post mapping aggregation and NAT coverage |
| Prefix / next hop / ASN | Partial | Prefix and next hop fields existed; no LPM context provider | Bounded IPv4/IPv6 longest-prefix-match provider and routing workspace |
| Field coverage | Missing | No optional-field denominator | Exporter-independent selected-period coverage matrix |
| Retention / sampling what-if | Missing | Storage capacity and sampling metadata existed | Explainable combined simulator with confidence and impact assumptions |

## Semantics

DSCP coverage uses a decoder provenance marker (`custom.dscp_present`). A DSCP value of zero is therefore not treated as missing when the exporter actually supplied the field. NAT coverage uses `custom.nat_present`; values are never inferred from an absent NAT field.

Routing uses a static prefix provider loaded from `routing-prefixes.json`. Lookups use longest-prefix matching for IPv4 and IPv6. The provider does not infer BGP path, peer, local preference or MED. A route entry is only shown when it was explicitly imported.

The simulator is a bounded what-if model. Raw retention uses observed daily bytes. Aggregate tiers use a documented 15% raw daily factor. Sampling scales estimated ingest and storage linearly; flow-count semantics are not silently multiplied. Results are labelled as estimates and never update configuration.

## API

- `GET /api/v1/engineering/routing`
- `GET /api/v1/engineering/qos`
- `GET /api/v1/engineering/nat`
- `GET /api/v1/engineering/coverage`
- `POST /api/v1/engineering/routes` (administrator; bounded static prefix table)
- `POST /api/v1/capacity/simulate`

All analytical ranges are limited to 31 days and storage results are capped at 100,000 rows. Route imports are capped at one million prefixes and persisted atomically. The simulator is explicitly simulation-only.

## Remaining limits

MRT/BMP/GoBGP live ingestion, historical route snapshots, NAT pool concurrency, exporter-specific template history, and exact aggregate rollups are not fabricated by this release. They require source metadata and a dedicated schema/retention design. The UI shows unavailable or zero coverage rather than presenting inferred values.

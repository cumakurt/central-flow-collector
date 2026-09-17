# API

The complete route inventory is in `openapi.yaml`. Browser sessions use the `fc_session` cookie plus `X-CSRF-Token` on state-changing requests. API clients use scoped Bearer tokens.

Public project information: `GET /api/v1/about` returns developer/contact/source/license metadata and the running build version. `GET /LICENSE` serves the full embedded GNU AGPL v3 license as plain text. These read-only routes work before sign-in and do not expose configuration or telemetry.

Key analytics endpoints:

- `GET /api/v1/analytics` — totals, Top-N dimensions and adaptive timeline for the selected filters/range.
- `GET /api/v1/analytics/service-catalog` — curated standard service presets (ports and transport protocols) used by the Service Timeline UI.
- `GET /api/v1/analytics/service-series` — one-scan multi-series timeline for up to eight standard services, custom ports, IP protocols or exporter-provided application values. Repeated selectors are supplied with `series_service`, `series_port`, `series_protocol` and `series_app`.
- `GET /api/v1/analytics/compare` — selected period versus immediately preceding equal period.
- `GET /api/v1/analytics/matrix` — bounded source/destination network matrix.
- `GET /api/v1/flows/page` — cursor-paged raw flow results.
- `GET /api/v1/flows/export` — CSV or JSON attachment using the same flow filters and time range; `limit=1..10000` (default 500). Flow Explorer requests up to 10,000 matching records. Invalid limits return HTTP 400; interactive query limits remain unchanged.
- `GET /api/v1/assets` — filtered endpoint ranking, with sent/received totals and exact peer counts.
- `GET /api/v1/conversations` — filtered bidirectional address/port pairs.
- `GET /api/v1/ip/{ip}` — IP-centric traffic detail.
- `GET /api/v1/exporters/health` — exporter packet/flow/error/sequence/template health.
- `GET /api/v1/storage/capacity` — retention, growth and capacity information where supported.
- `POST /api/v1/reports/export` — PDF/XLSX/CSV/JSON output using the submitted filters/time range.
- `GET /api/v1/live/events` — authenticated SSE updates.

Flow filters are server-side and include source/destination/host, standard `service`, either-endpoint `port`, directional ports, protocol, bytes/packets, exporter/listener/node, ASN/country/site, interfaces, direction, application, NAT fields and time bounds as supported by the query parser. The public API has no tenant selector.

## Endpoint and conversation analysis

`assets`, `conversations` and `ip/{ip}` accept the same flow predicates used by the visual Flow Lens: `src_ip`, `dst_ip`, `host`, `src_cidr`, `dst_cidr`, `cidr`, `service`, `port`, `src_port`, `dst_port`, `ip_protocol`, `app`, `exporter`, `ingress_if`, `egress_if`, `src_as`, `dst_as`, `asn`, `country`, `site`, `tcp_flags`, and minimum/maximum `bytes`, `packets` and `duration_ms`. All predicates must match the underlying flow **before** aggregation. Country, ASN and host match either endpoint. A directional port predicate can consequently exclude the reverse half of a conversation. Duration is zero when either timestamp is missing or the end precedes the start.

Both ranking endpoints accept `metric=bytes|packets|flows` (default `bytes`); assets also accepts `metric=peers`. Sorting happens before applying `limit` (1–1000, default 100). Ties use ascending endpoint or conversation identity. Result arrays retain their existing shape. Invalid metrics or filters return HTTP 400.

`from` and `to` are RFC3339 timestamps, inclusive. Ranges are limited to 31 days and default to the last hour. IP detail has the same range limit and uses `limit=1..100`, default 20, for its ranked subresults. Its path IP remains independent of an optional `host` predicate, allowing a peer lens at the API level. Legacy tenant selectors remain ignored by the HTTP handlers.

Examples:

```text
/api/v1/assets?metric=peers&limit=50&ip_protocol=TCP&src_cidr=10.0.0.0%2F8
/api/v1/conversations?metric=packets&limit=25&dst_port=443&min_duration_ms=1000
/api/v1/ip/10.0.0.1?host=10.0.0.2&ip_protocol=TCP
```

See [Analytical views](ANALYSIS-VIEWS.md) for percentile methodology, ranking limits and portal drill-down behavior.

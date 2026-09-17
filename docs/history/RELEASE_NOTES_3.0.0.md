# Central Flow Collector v3.0.0 — Release Notes

v3.0.0 is the enterprise resilience and flow-intelligence release built on the audited v2.0.1 baseline.

## Reliability and performance

- ClickHouse failed writes are persisted to an fsync-backed local spool instead of being immediately lost after retry exhaustion.
- Spool size is quota bounded and replay is ordered/automatic when ClickHouse becomes writable again.
- Storage telemetry now exposes spool files, bytes, flows spooled and flows replayed.
- Existing bounded listener queues are complemented by per-exporter token-bucket packet-rate protection, preventing one exporter from monopolizing collector capacity.
- A five-minute ClickHouse materialized rollup (`flows_5m`) is created for scalable top-N/dashboard workloads.

## Security

- Granular roles include `security_admin`, `network_operator`, `analyst`, and `read_only`; legacy roles remain accepted for upgrades.
- API tokens can be restricted by permission scopes and source CIDRs. Restrictions are enforced on every bearer-authenticated request.
- Diagnostics (`/debug/pprof`) are disabled by default and require both explicit configuration and `diagnostics.read` permission.
- Webhook integrations can be HMAC-SHA256 signed with `X-FlowCollector-Signature`.
- Existing tamper-evident HMAC audit chaining, MFA/passkeys, OIDC/LDAP, tenant isolation, CSP/DOM hardening, CSRF and secure token hashing are retained.

## Flow intelligence

- Added explainable detections for outbound data-exfiltration volume, DNS/DoT flow-volume anomalies, internal administrative-service lateral movement and distributed-target/DDoS-like fan-in.
- Existing vertical/horizontal scan, SYN anomaly, periodic beacon, traffic-spike, connection-burst, large-transfer, baseline anomaly, threat-intelligence and risk/correlation capabilities remain active.
- Added active NetFlow v9/IPFIX template inventory including exporter, observation domain, template ID, field count and age.

## Operations and UI

- Portal navigation is permission aware instead of relying only on the administrator/non-administrator split.
- API-token UI exposes scopes and source CIDR restrictions.
- Storage view exposes spool pressure/replay state.
- Exporter Health now includes an active template inventory.
- Existing live SSE dashboard, cross-filtering, topology, query builder, saved searches, Geo/ASN/site enrichment, IPv4/IPv6, NAT fields, HA fleet management, global dedup, config validation/diff/apply/rollback and alert/report integrations are retained.

## Release engineering

- `scripts/release-check.sh` executes unit/integration tests, `go vet`, frontend/shell syntax checks and short fuzz campaigns for all four network decoders.
- Release packaging generates SPDX 2.3 and CycloneDX 1.5 SBOMs and SHA-256 checksums.
- Linux amd64 and arm64 static binaries are built with embedded version/commit/build-time metadata.

## Operational notes

The write spool is not a replacement for ClickHouse backup. Set `clickhouse_spool_max_bytes` to a value appropriate for the host filesystem and monitor spool growth. Diagnostics should remain disabled except during controlled troubleshooting. API tokens with no explicit scopes retain role-default behavior for upgrade compatibility; new automation tokens should use the minimum required scopes.

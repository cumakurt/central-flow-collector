# Central Flow Collector v3.0.0 — Validation Report

Date: 2026-09-13
Release identity: `3.0.0 / release-v3.0.0`

## Completed validation

- `go test ./...` — PASS across all packages.
- `go vet ./...` — PASS.
- Front-end JavaScript syntax (`node --check internal/api/static/app.js`) — PASS.
- Installer shell syntax (`bash -n install.sh uninstall.sh`) — PASS.
- Decoder fuzz campaigns — PASS with no panic/crash:
  - NetFlow v5: 88,732 executions in the final release-check run.
  - NetFlow v9: 114,933 executions.
  - IPFIX: 138,067 executions.
  - sFlow: 139,475 executions.
- Race detector — PASS when run in split groups:
  - `go test -race ./internal/auth` — PASS (~30.9 s in the validation run).
  - `go test -race ./internal/api` — PASS; final post-hardening rerun completed in 25.8 s.
  - all remaining Go packages excluding auth/api — PASS.
  - A single bulk `go test -race ./...` invocation exceeded the execution sandbox time limit because PBKDF2 becomes very expensive under the race detector; it did not report a data race before timeout. Split execution provided full package coverage.
- Production builds — PASS for Linux amd64 and arm64:
  - `flowcollector`
  - `flowgen`
  - `chbench`
- `dist/checksums.txt` verification — PASS for all six binaries and both SBOM files.
- Runtime smoke test using the final amd64 binary — PASS:
  - config validation: PASS
  - `/ready`: PASS
  - `/health`: `{"status":"ok"}`
  - 200 synthetic NetFlow v5 datagrams accepted
  - 200 flows / 2,000 packets recorded
  - storage write errors: 0
  - storage drops: 0
  - graceful SIGTERM shutdown: PASS
  - diagnostics disabled: `/debug/pprof/` returns 404
- NetFlow v5 30-flow decoder benchmark on the validation host:
  - 15,454 ns/op
  - 38,416 B/op
  - 96 allocs/op

Raw validation artifacts are stored in `validation/`.

## Major v3.0.0 changes validated

- Durable ClickHouse disk spool/WAL with quota, fsync, ordered replay and telemetry.
- Per-exporter token-bucket rate limiting to contain noisy/malicious exporters.
- Granular role permissions plus API-token scopes and source-CIDR restrictions.
- Authenticated, default-disabled pprof/trace diagnostics.
- IPFIX/NetFlow template inventory API/UI.
- New explainable detections for outbound exfiltration, DNS anomaly, lateral movement and DDoS targets.
- Five-minute ClickHouse materialized rollup layer for dashboard/top-N scalability.
- HMAC-SHA256 signed webhook notifications.
- SBOM generation (SPDX + CycloneDX), deterministic release metadata and checksums.
- Existing topology, live SSE, Geo/ASN enrichment, NAT visibility, saved searches/query builder, alert operations, cluster/HA, config validation/diff/apply/rollback and audit chain retained and regression-tested.

## Environment-dependent validation not executed

The validation environment did not provide production external services. Therefore the following were not exercised end-to-end against live infrastructure:

- a real ClickHouse cluster/failover topology (schema/spool behavior is covered by tests and HTTP mocks);
- external OIDC identity provider;
- external LDAP/Active Directory server;
- external SMTP/Telegram/SIEM/SOAR endpoints;
- sudo/systemd installation on a fresh production host.

These are integration-environment limitations, not hidden test failures. Before a production rollout, run staging tests against the target ClickHouse topology and identity/notification systems.

## Final rebuild revalidation

After the release binaries were rebuilt from the final source tree, an additional fresh validation pass was performed. `go test -count=1 ./...`, `go vet`, JavaScript/shell syntax checks, split race coverage, all four decoder fuzz targets, SBOM parsing/checksums and a fresh amd64 UDP runtime smoke test passed. The rebuilt binary processed 200 synthetic NetFlow v5 datagrams as 200 flows / 2,000 packets with zero storage write errors and zero drops; pprof remained disabled with HTTP 404. See `validation/FINAL_REVALIDATION_3.0.0.md` and the `validation/revalidation-*` raw artifacts.

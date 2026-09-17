# Central Flow Collector v3.2.0 — Validation Report

Release identity: `3.2.0 / release-v3.2.0`
Final build timestamp embedded in binaries: `2026-09-14T10:23:03Z`
Build Go version: `go1.23.2`

## Release gate

The final source tree passed the following release checks in this environment:

- `go test -count=1 ./...` — PASS.
- `go vet ./...` — PASS.
- `gofmt` source check — PASS.
- JavaScript syntax (`node --check`) and release/install shell syntax (`bash -n`) — PASS.
- Race detector — PASS for `internal/auth`, `internal/api`, all remaining packages, plus a final analytics-specific race rerun after the high-cardinality persistence changes.
- NetFlow v5/v9, IPFIX and sFlow fuzz targets — PASS. A dedicated 10-second fuzz pass executed approximately 1.08M / 0.67M / 1.11M / 1.22M cases respectively without panic/crash. The final release gate re-ran all four fuzz targets against the packaged source.
- NetFlow v5 decoder micro-benchmark on the build host: `9126 ns/op`, `38416 B/op`, `96 allocs/op` for a 30-record packet.
- Linux amd64 and arm64 static release builds — PASS for `flowcollector`, `flowgen`, `chbench`, and `flowbench` (8 binaries total).
- SPDX 2.3 and CycloneDX 1.5 SBOM generation/parsing — PASS.
- `dist/checksums.txt` verification — every binary and SBOM OK.
- Example configuration validation — PASS.
- Accidental build-host temp-path and obvious private-key/populated-secret scan — PASS.

Raw logs are retained under `validation/`.

## Runtime high-cardinality smoke/load test

The final amd64 `flowcollector` binary was started with local storage, three live UDP listeners and the normal v3.2 analytics features enabled. `flowbench` then sent randomized NetFlow v5 traffic specifically chosen to create high source/destination cardinality.

- Sender: 2,996 UDP datagrams in 3 seconds.
- Records generated/accepted: 89,880 flows.
- Sender throughput: approximately 998 packets/s / 29,950 flows/s / 1.39 MiB/s.
- Collector `flowcollector_flows_total`: 89,880.
- Storage write errors: 0.
- Storage dropped flows: 0.
- Dedup duplicates: 0.
- Process RSS / high-water after the load: approximately 211 MiB.
- Seasonal baseline hosts: bounded at 20,000.
- Behavior Analytics profiles: bounded at 20,000.
- Scan states: bounded at 50,000.
- Beacon states: bounded at 50,000.
- Excess analytics-state admissions were counted in `flowcollector_analytics_state_dropped_total`; these are analytics profile/state admissions, not dropped flow records.
- `/ready` remained healthy before and after the load.
- `/debug/pprof/` returned HTTP 404 with diagnostics disabled by default.
- SIGTERM shutdown returned rc=0 without forced termination.
- Persisted baseline snapshot: approximately 2.7 MiB; Behavior Analytics snapshot: approximately 14 MiB.

A preliminary version of this same smoke test exposed high-cardinality memory amplification during analytics-state persistence. The release was not accepted at that point. v3.2 was hardened with sparse baseline buckets, bounded analytics state admission, tenant-isolated baseline keys, bounded inner unique sets, tenant-scoped generated alert IDs, and capacity/drop telemetry. The final smoke result above validates the corrected implementation.

## Production hardening and SOC/NDR functions covered

The release contains and unit/integration tests exercise:

- Linux `recvmmsg()` batch receive and exporter-sticky worker sharding.
- Reproducible `flowbench` UDP load generation and latency/allocation reporting.
- Segmented CRC32 WAL/spool replay, corruption quarantine and crash-temp recovery.
- ClickHouse query limits, clustered table support, materialized rollups and optional operator-provisioned hot/cold storage-policy movement.
- Cluster key rotation, expected-node quorum state, deterministic coordinator and rendezvous exporter assignment.
- Optional cluster mTLS configuration/validation.
- Behavior Analytics v2 persistence and explainable anomaly logic.
- Central MITRE ATT&CK metadata mapping.
- Validated generic, Arkime and Security Onion PCAP pivots.
- Tenant-scoped Investigation Workspace.
- `@env:` / `@file:` secret providers.
- Granular RBAC, scoped/CIDR API tokens, tamper-evident audit chain, SIEM/SOAR outputs, dashboard SSE/cross-filtering, topology and NAT/IPv6 query support inherited from the enterprise baseline.

## Environment-dependent acceptance tests not claimed

The build environment did not provide an external production ClickHouse Keeper/shard/replica deployment, external OIDC/LDAP/SMTP/SIEM services, or live Arkime/Security Onion systems. Their configuration, validation, serialization and mocked/test-server paths are covered, but a deployment-specific end-to-end acceptance test is still required before enabling them in production.

Likewise, this sandbox does not justify publishing a universal “10M flows/s” product claim. v3.2 includes the benchmark harness and kernel/collector controls required to run 1M/5M/10M generated-flow steps on target hardware; sustainable end-to-end throughput must be measured with that deployment's NIC, kernel buffers, CPU, enabled analytics/enrichment, and ClickHouse topology.

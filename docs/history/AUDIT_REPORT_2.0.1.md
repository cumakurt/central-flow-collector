# Central Flow Collector v2.0.1 — Deep Audit & Remediation Report

Date: 2026-09-13
Base reviewed: v2.0.0
Resulting release: v2.0.1

## Scope

The codebase was reviewed for architecture, correctness, maintainability, functional behavior, web UI safety, cybersecurity, concurrency, performance, latency, memory/GC pressure, resource consumption, build reproducibility and deployment practicality. The review covered approximately 20k lines of Go plus the embedded dependency-free JavaScript/CSS portal, shell installers, configuration, storage and protocol decoders.

## High-impact findings fixed

### 1. Authentication-wide PBKDF2 lock contention — HIGH

`Manager.Login` held the manager mutex while performing 310,000 PBKDF2-SHA256 iterations. A single login could therefore block unrelated session/token operations and concurrent logins, increasing latency and creating an avoidable application-level DoS amplification point.

Fix: expensive password verification now executes outside the global manager mutex. The account is re-read after verification so concurrent password reset, disable, role or tenant changes take effect before a session is issued. Token/CSRF RNG failures are no longer ignored.

### 2. Bearer-token hot path was O(n) plus synchronous disk write — HIGH

Every bearer-authenticated request scanned every API token and rewrote `api-tokens.json` to update `last_used`. Request latency and disk I/O therefore scaled with token count and traffic rate.

Fix: persistent token hashes are indexed in memory for O(1) lookup. Last-used state is updated in memory on the request hot path; persistent token mutations subsequently serialize current state. Create/revoke/load keep the index consistent. A regression test verifies repeated bearer authentication does not rewrite the token file.

### 3. UDP ingestion allocated a fresh packet buffer per accepted datagram — MEDIUM/HIGH performance

The read loop copied every accepted UDP packet into a newly allocated byte slice before queueing it. At high packet rates this created avoidable allocation and GC pressure.

Fix: listener processing now uses a bounded `sync.Pool` of 65,535-byte UDP buffers. Buffers are returned on read errors, policy rejection, queue drop and after worker processing. This removes the per-accepted-packet copy/allocation from the hot path while preserving bounded queues.

### 4. Tenant collision in exporter rejection/health bookkeeping — HIGH correctness / isolation

Rejected exporter keys did not use the same tenant-qualified key format as accepted exporters. Exporter-down health alert suppression keys also omitted tenant. Identical exporter/listener tuples in different tenants could therefore collide operationally.

Fix: rejection/exporter keys are tenant-qualified, `RejectionStat` carries tenant, health-alert suppression keys include tenant, and exporter-down alerts propagate tenant.

### 5. Rich-table DOM injection surface — HIGH web security

The portal's generic rich-table helper used `innerHTML` for entire rows when interactive buttons/spans were needed. Several rows mixed trusted UI fragments with server-returned strings, making stored DOM injection possible if attacker-influenced text reached a rich cell.

Fix: rich table cells now pass through a central allow-list sanitizer. Only `BUTTON`, `SPAN` and `CODE` elements are retained; only `class`, `title` and `data-*` attributes survive. Table headers are escaped. Existing event binding remains external and CSP-compatible.

### 6. JSON parser accepted a valid first object with trailing JSON value — MEDIUM

The API decoder parsed one JSON value but did not verify EOF. Concatenated JSON values could therefore be partially accepted.

Fix: request decoding now requires EOF after the first value and rejects additional/trailing JSON payloads.

### 7. Browser hardening headers incomplete — MEDIUM

Existing CSP and frame/content headers were good but did not explicitly deny plugins/objects, base URI changes, external form targets or sensitive browser features.

Fix: CSP now adds `base-uri 'self'`, `object-src 'none'`, `frame-ancestors 'none'`, and `form-action 'self'`. Added `Permissions-Policy`, `Cross-Origin-Opener-Policy`, and HSTS when the application itself is serving TLS.

### 8. Repeated clock reads in flow loop — LOW performance

The decoded-flow loop repeatedly called `time.Now().UTC()` for dedup and alert timestamps.

Fix: one timestamp is captured per decoded packet/result and reused where semantically equivalent.

## Positive findings retained

- No third-party Go module dependencies are declared; the supply-chain footprint is small.
- Production binaries are built with `CGO_ENABLED=0`, `-trimpath`, stripped symbols and static linking.
- HTTP server has explicit read-header, read, write, idle and max-header limits.
- API request bodies are capped and unknown JSON fields are rejected.
- Session cookies are HttpOnly and SameSite=Strict; CSRF protection is enforced for cookie-authenticated mutations.
- Password hashes use salted PBKDF2-SHA256 with 310,000 iterations and constant-time comparison.
- ClickHouse identifiers are validated and query values use parameters in the main query path.
- Storage queues, listener queues, dedup state and several analytics structures are bounded.
- Tenant scoping is enforced server-side for non-administrator access paths.
- OIDC/LDAP transport and identity checks, MFA/passkey flows, audit chaining and backup integrity already have dedicated tests.

## Validation performed

- `go test ./...` — PASS
- `go vet ./...` — PASS
- `go test -race` for all packages excluding auth/API in one batch — PASS
- `go test -race ./internal/auth` — PASS (33.438s)
- `go test -race ./internal/api` — PASS (26.372s)
- `node --check internal/api/static/app.js` — PASS
- `bash -n` for installer/uninstaller/test scripts — PASS
- NetFlow v5 benchmark (30 flows): ~20.5 µs/op, 38,416 B/op, 96 allocs/op on the provided Xeon sandbox
- Production cross-build: linux/amd64 + linux/arm64 for `flowcollector`, `flowgen`, `chbench` — PASS
- Runtime smoke test with production amd64 binary — PASS
  - config validation: PASS
  - `/ready`: ready=true
  - 200 generated NetFlow v5 datagrams ingested
  - metrics: 200 flows, 2,000 packets, 10,344,564 bytes
  - storage write errors: 0
  - storage drops: 0
  - dedup duplicates: 0
  - graceful SIGTERM shutdown: PASS
- SHA-256 checksums generated for all six production binaries.

The first monolithic `go test -race ./...` attempt exceeded the sandbox command time window while running expensive PBKDF2/race workloads. The suite was then split: all non-auth/API packages passed race detection, followed by full auth and full API race runs, both passing.

## Environment-limited checks

The following require infrastructure not present in this sandbox and were not falsely reported as executed:

- Real external ClickHouse throughput/integration benchmark against a live ClickHouse server.
- Privileged installer/systemd integration scripts requiring sudo and host service management.
- Real OIDC/LDAP/SMTP/webhook external-provider integration.
- Full interactive Chromium visual walkthrough. Frontend syntax and embedded static regression tests passed, but this environment did not provide a local browser automation target for the packaged service.

## Remaining engineering considerations

- UDP telemetry is inherently unauthenticated/loss-prone; source-IP policy is authorization by network identity, not cryptographic exporter authentication. Network ACLs/VPN/IPsec should protect telemetry networks where appropriate.
- Local JSONL storage is suitable for labs/smaller deployments; high-volume production should use ClickHouse.
- CSP still permits `'unsafe-inline'` for styles because the current portal uses inline style attributes. Removing these into CSS classes would allow a stricter style policy in a future release.
- PBKDF2 is sound and deliberately expensive, but a future major-format migration could evaluate Argon2id while preserving upgrade compatibility.
- High-rate production sizing should benchmark the real NIC/kernel receive path, ClickHouse cluster and intended exporter mix; synthetic decoder microbenchmarks are not a complete capacity model.

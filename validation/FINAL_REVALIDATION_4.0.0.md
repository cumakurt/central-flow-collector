# Final Revalidation — Central Flow Collector v4.0.0

- Full cache-free Go tests: PASS
- go vet: PASS
- gofmt/static JS/shell syntax: PASS
- Split race detector coverage: PASS
- NetFlow v5/v9, IPFIX, sFlow fuzzing: PASS
- Reporting PDF/CSV/JSON/XLSX tests: PASS
- Decoder benchmark recorded
- 50k-row query benchmark recorded
- Linux amd64/arm64: 10 release binaries built
- Runtime NetFlow v5 smoke/load: 111,780 flows; 0 listener drops; 0 storage drops; 0 storage write errors
- /ready and /health: PASS
- diagnostics/pprof default-off: PASS (404)
- SIGTERM graceful exit: PASS (rc=0)
- amd64/arm64 Debian packages: built and inspected; embedded collector hashes match dist binaries
- SPDX 2.3 + CycloneDX 1.5 SBOM: generated and JSON-validated
- dist SHA-256 verification: PASS
- source manifest verification: PASS
- common secret/private-key pattern scan: no match
- Docker/Compose/Helm/RPM build sources included; Docker/Podman/Helm/rpmbuild unavailable in this sandbox, so those external tool executions are not claimed.

See `../VALIDATION_REPORT_4.0.0.md` and the raw files in this directory for exact evidence.

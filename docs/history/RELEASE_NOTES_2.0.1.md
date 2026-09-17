# Central Flow Collector v2.0.1 — Release Notes

v2.0.1 is a security, correctness and performance hardening release over v2.0.0. It keeps the v2.0 administration and v1.9 portal feature set while reducing authentication contention, bearer-token disk I/O and UDP packet allocation pressure; it also fixes tenant-qualified exporter health bookkeeping and hardens JSON/browser boundaries.

## Main changes

- PBKDF2 verification no longer holds the global auth mutex.
- API bearer authentication uses O(1) hash lookup and no longer rewrites token state on every request.
- UDP datagram buffers are pooled and recycled through the listener/worker pipeline.
- Rejection/exporter/health keys and exporter-down alerts are tenant-aware.
- Rich HTML table cells use an allow-list DOM sanitizer.
- API JSON parsing rejects multiple/trailing values.
- CSP and browser security headers are strengthened.
- Added regression tests for the above behavior.
- Version bumped to 2.0.1 and linux/amd64 + linux/arm64 binaries rebuilt.

See `AUDIT_REPORT_2.0.1.md` for the complete review, validation evidence, limitations and remaining recommendations.

# Central Flow Collector v3.2.0 — Release Notes

v3.2.0 is the Production Hardening, Scale and SOC/NDR release built on the v3.0.0 enterprise baseline.

## Production scale and resilience

- Linux UDP listeners support batched `recvmmsg()` reads with configurable batch size and exporter-sticky worker sharding.
- New `flowbench` tool provides repeatable NetFlow v5 UDP load generation with target/unlimited PPS, multiple writers, flow/packet throughput, write p50/p95/p99, allocation and GC metrics.
- ClickHouse failed writes use segmented `CFCWAL1` records with CRC32, bounded segment/quota controls, optional fsync, crash-temp recovery, corruption quarantine and legacy spool replay compatibility.
- Interactive ClickHouse requests are bounded independently with timeout, result-row and execution-time controls.
- Optional preconfigured ClickHouse storage-policy cold-tier movement is supported without pretending to provision operator storage volumes automatically.

## HA and cluster hardening

- Expected-node quorum state and deterministic coordinator reporting.
- Rendezvous-hash exporter assignment for stable collector ownership decisions.
- Multiple accepted cluster tokens for non-disruptive key rotation.
- Optional cluster client-certificate mTLS in addition to bearer authentication.

## SOC/NDR workflow

- Persisted Behavior Analytics v2 profiles learn services, countries, ASNs, peers, UTC activity hours and EWMA volume baselines.
- Explainable detections cover novel services/countries, off-hours activity and unusually large per-flow volumes in addition to existing scan, beaconing, exfiltration, DNS, DDoS and lateral-movement logic.
- Central MITRE ATT&CK metadata is attached to supported detections and exposed through investigations.
- Investigation Workspace combines host flow summaries, peers/ports, behavior profile, detections, ATT&CK context, risk score and validated PCAP pivots.
- PCAP pivots support generic, Arkime and Security Onion URL generation with strict IP/port/protocol/time-range validation. The collector does not retrieve or store packet captures itself.

## Security and operations

- Secret references support `@env:NAME` and `@file:/absolute/path` for ClickHouse, OIDC, LDAP and notification credentials.
- Restored configuration passes through the same secret-resolution path as normal startup.
- High-cardinality analytics state is explicitly bounded. Seasonal baselines use sparse buckets, baseline keys include tenant identity, generated alert IDs are tenant-scoped, and dropped state admissions are observable through health/Prometheus metrics.
- Existing granular RBAC, token scopes/CIDR restrictions, HMAC audit chain, SIEM/SOAR formats, signed webhooks, diagnostics controls and tenant isolation remain enforced.

## Compatibility

Configuration remains backward compatible with v3.0.0 defaults. New features are opt-in where they introduce external requirements such as mTLS, PCAP providers or ClickHouse hot/cold storage policy integration.

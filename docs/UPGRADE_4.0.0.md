# Upgrade to v4.0.0

1. Back up `/etc/flowcollector`, local metadata/data and ClickHouse as appropriate.
2. Stop v3.x collectors and save the old binaries for rollback.
3. Install the v4 binary and run `config validate` against the existing config.
4. Remove deprecated tenant/threat/PCAP/behavior settings when convenient; v4 ignores those legacy keys for transition safety.
5. Review roles. `viewer` becomes `read_only`; `operator`, `network_operator` and `security_admin` become `analyst`.
6. Start v4 and verify `/ready`, exporter health, listener drops, storage write errors and a known flow query.
7. Validate reports and saved views before deleting the rollback copy.

Existing flow storage remains compatible; the historical ClickHouse `tenant` column is retained but v4 does not expose tenant selection or tenant-scoped authorization.

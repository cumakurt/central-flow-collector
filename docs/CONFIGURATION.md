# Configuration

`config.example.yaml` is the canonical v4 example. Validate before restart:

```bash
flowcollector config validate --config /etc/flowcollector/config.yaml
```

Important sections are `web`, `storage`, `security`, `oidc`, `ldap`, `enrichment`, `analytics`, `notifications`, `cluster` and `listeners`.

Secrets may use `@env:VARIABLE` or `@file:/path`. Keep ClickHouse, OIDC/LDAP and cluster secrets outside world-readable YAML.

### Analytics

`baseline_enabled` enables operational hour-of-week traffic comparison. `max_tracked_hosts` and `max_dimension_keys` bound high-cardinality state. No NDR/IDS behavior engine exists in v4.

### ClickHouse

Use `clickhouse_batch_size`, `clickhouse_queue_size`, query time/result limits and spool controls to protect ingestion. Optional cluster/distributed-table fields support scale-out ClickHouse. Storage-policy/cold-volume fields can integrate an administrator-defined ClickHouse hot/cold policy.

### Upgrade compatibility

v3 tenant/threat/PCAP/behavior configuration keys are accepted only as deprecated ignored input so older files can be cleaned gradually; they are not active features.

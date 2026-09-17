# ClickHouse Logical Backup — v1.6.0

The collector can create a portable logical flow backup through the configured ClickHouse HTTP(S) endpoint.

## Create

```bash
flowcollector clickhouse-backup create \
  --config /etc/flowcollector/config.yaml \
  --output /secure/flows.jsonl.gz
```

Optional `--from` and `--to` RFC3339 timestamps bound the export. Rows are streamed as `JSONEachRow` through gzip; the complete table is never intentionally materialized in collector memory.

A sibling `.manifest.json` records format version, database/table, time bounds, row count and SHA256 of the compressed archive.

## Verify

```bash
flowcollector clickhouse-backup verify --archive /secure/flows.jsonl.gz
```

Verification checks the manifest and compressed-archive SHA256 before restore.

## Restore

```bash
flowcollector clickhouse-backup restore \
  --config /etc/flowcollector/config.yaml \
  --archive /secure/flows.jsonl.gz \
  --force
```

Restore is intentionally force-gated and streams decompressed `JSONEachRow` into ClickHouse.

## Scope

This feature is useful for portable exports, migration and smaller DR workflows. It does not preserve every ClickHouse server-level object/settings and is not a replacement for native ClickHouse backup/replication in large HA deployments.

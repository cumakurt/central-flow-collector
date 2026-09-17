# Collector Cluster / Fleet / Global Dedup — v1.7.0

v1.7.0 extends the authenticated v1.6 heartbeat registry into a deliberately small fleet-control and active-active dedup plane. It is not a general distributed consensus system.

## Central node / shared token

`install.sh` creates `/etc/flowcollector/cluster.token` with restricted permissions. Central endpoints use this separate bearer token rather than browser/API-user tokens:

```text
POST /api/v1/cluster/heartbeat
POST /api/v1/cluster/dedup
Authorization: Bearer <shared-cluster-token>
```

Remote plaintext HTTP is rejected by configuration validation unless explicitly permitted. Normal HTTPS hostname/CA validation remains enabled.

## Heartbeat registry

Heartbeats report node ID, region, version, start time, storage backend, health, config version and bounded metrics. Registry state is persisted under the collector data directory and nodes are reported online/degraded/offline according to timeout.

## Fleet commands

Administrators may queue only these allowlisted actions:

- `reload_policies` — atomically reload the persisted exporter-policy file; invalid files leave the active compiled policy intact.
- `restart_service` — acknowledge the command, gracefully drain/shutdown and exit with the systemd restart code.

Commands are persisted, retried on later heartbeats until acknowledged, and audit logged. Arbitrary command execution is intentionally absent.

## Global dedup coordinator

Enable a coordinator on the central node:

```bash
sudo ./install.sh --cluster-global-dedup
```

Configure an edge collector:

```bash
sudo ./install.sh \
  --cluster-heartbeat-url https://central.example/api/v1/cluster/heartbeat \
  --cluster-global-dedup \
  --cluster-global-dedup-url https://central.example/api/v1/cluster/dedup \
  --cluster-token-file /root/central-cluster.token
```

The fingerprint uses exporter/protocol/observation-domain/sequence plus normalized 5-tuple, timing, counters and interface/VLAN data. The coordinator state is TTL bounded and entry-count bounded. The first collector submitting a fingerprint is accepted; overlapping collectors submitting the same fingerprint inside the window are rejected before analytics/alert/storage.

If the coordinator request times out or fails, ingestion **fails open** and increments the global dedup error counter. This choice protects telemetry availability at the cost of possible duplicates during coordinator outages.

Node-local dedup remains enabled independently and bounded by `analytics.dedup_*` settings.

## Active-active scope

With exporters sending identical flow telemetry to multiple collectors, a shared ClickHouse backend and global dedup coordinator provide practical active-active ingestion readiness. v1.7.0 does not claim leader election, distributed config consensus, transactional exactly-once semantics or automatic exporter rerouting.

# Architecture

## Runtime data path

Each UDP listener owns a bounded packet queue. Linux may batch datagram reads with `recvmmsg`. Workers decode NetFlow v5/v9, IPFIX or sFlow into one normalized `model.Flow`; v9/IPFIX template state is isolated by exporter/observation-domain. Policy validation and optional prefix Geo/ASN/site enrichment occur before analytics/storage.

The operational analytics engine keeps bounded aggregates and a persisted hour-of-week traffic baseline. It produces traffic-volume deviations, large-flow and exporter-availability events only; it does not classify attacks.

Storage is asynchronous. The local backend persists JSONL segments; ClickHouse uses bounded batches/queues, request/query limits, five-minute aggregate rollups and an optional CRC-protected spool/WAL for transient write failure. The web/API reads through the storage `Analyze` contract so dashboards, reports and interactive analytics share the same totals.

## Single organization

v4 has one organization boundary. Authentication is local, OIDC or LDAP; authorization is role/permission based. The three canonical roles are Administrator, Analyst and Read Only. Historical `tenant` columns are a compatibility detail only and are never accepted as a public query boundary.

## Scale and availability

Collector nodes may be deployed independently or use heartbeat/global-dedup coordination for availability. ClickHouse can be configured with replicated/distributed tables. This is infrastructure scale-out, not multi-tenancy.

# Offline Enrichment

v1.2.0 intentionally performs enrichment from local operator-supplied data and never blocks packet ingestion on DNS or internet lookups.

## Prefix file

CSV format:

```text
cidr,country,asn,as_name
203.0.113.0/24,TR,64510,Example Transit
2001:db8::/32,US,64512,Example IPv6 Network
```

Country is treated as an operator/database-provided label. ASN may be written into the canonical flow only when the exporter did not provide an ASN. If the exporter supplied it, the exporter value wins. Provenance is kept under `custom.src_as_source` / `custom.dst_as_source` and geo labels are tagged as `offline_prefix`.

Prefix records and local sites use longest-prefix matching. This permits a broad site such as `10.0.0.0/8` plus a more specific `10.20.0.0/16` site.

## Site mappings

Sites are stored atomically in `<data_dir>/sites.json`. They can be managed from **Sites & Enrichment** or `/api/v1/sites`. Each entry has an ID, display name, CIDR, optional description and tags.

## Reload

Replacing the prefix CSV does not require process restart. Administrators may call `POST /api/v1/enrichment/reload` or use the portal button. Parsing is completed before the in-memory database is replaced; invalid input returns an error instead of silently installing partial data.

# Service Traffic Timeline

The **Traffic → Service Timeline** view compares service traffic over the same selected time range without downloading raw flow populations to the browser. Up to eight series can be displayed on one chart. Each selected series keeps a stable, distinct chart color.

## Selectors

The view supports four selector types:

- **Standard service** — curated protocol-aware port definitions such as SMTP (TCP 25/465/587), DNS (TCP/UDP 53), HTTP/HTTPS, POP3, IMAP, SSH/SFTP, RDP, FTP, DHCP, NTP, SNMP, LDAP/LDAPS, SMB, Kerberos, Syslog, MySQL, PostgreSQL, Microsoft SQL Server, Redis, MongoDB, WinRM, Telnet and SIP.
- **Custom port** — an arbitrary port with TCP, UDP, SCTP or Any transport. Port matching is symmetric: source or destination can be the service endpoint.
- **IP protocol** — TCP, UDP, ICMP, ICMPv6, GRE, ESP, OSPF or SCTP.
- **Application** — an application name/ID already present in exporter flow metadata. The collector does not infer Layer-7 applications with DPI.

Selections are encoded in the URL using repeated `series_service`, `series_port`, `series_protocol` and `series_app` parameters, so a comparison can be bookmarked or shared. The server enforces a maximum of eight series per request.

## Metrics and time ranges

The chart can show **Bandwidth**, **Bytes**, **Packets** or **Flows**. It uses the portal's existing time picker, including the ready-made ranges and custom `from`/`to` periods. Bucket size is chosen adaptively so long periods such as 30 days remain bounded and readable.

The local storage backend calculates all selected series in one file scan. The ClickHouse backend generates one service-series query and assigns matching flows to selected series in that query, rather than issuing one full analytics query per selected service. A flow can intentionally contribute to more than one series when selectors overlap.

## Drill-down

Clicking a non-empty point/interval opens **Flow Explorer** with:

1. the selected series filter,
2. the exact chart bucket time range, and
3. the active compatible Flow Lens filters.

The service filter is protocol-aware and matches the service port on either endpoint. Selecting a whole series card opens Flow Explorer for that service over the full selected time range. Flow rows expose the collected flow metadata including packet and byte counters.

The collector does **not** retain historical packet payloads/PCAP as part of this feature. Therefore a drill-down can show the matching flows and their packet counts/flow fields, but it cannot reconstruct individual historical packet payloads that were never captured.

## HTTP API

### Service catalog

```text
GET /api/v1/analytics/service-catalog
```

Requires `analytics.read`. Returns the curated service list and `max_series`.

### Multi-series timeline

```text
GET /api/v1/analytics/service-series?from=...&to=...&series_service=smtp&series_service=dns&series_port=tcp:8443
```

Supported repeated selectors:

- `series_service=<catalog-id>`
- `series_port=<tcp|udp|sctp|any>:<1..65535>` (the protocol prefix may be omitted for Any)
- `series_protocol=<IP protocol name or number>`
- `series_app=<exporter application value>`

The response contains totals and aligned timeline points for every requested selector. Existing server-side flow predicates can be supplied with the same request to scope the analysis.

### Flow drill-down filters

The normal flow query parser additionally accepts:

- `service=<catalog-id>` — protocol-aware standard-service match on either endpoint.
- `port=<1..65535>` — exact port match on source **or** destination endpoint.

The existing `src_port` and `dst_port` remain directional and unchanged.

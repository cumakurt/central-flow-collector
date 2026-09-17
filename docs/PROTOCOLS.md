# Protocol support

The collector accepts NetFlow v1, v5, v7, v8, v9, IPFIX (NetFlow v10),
and sFlow v5 over their supported transports. Support is defined by the capabilities below; this is not a
claim that every historical protocol, transport, vendor extension, or
information element is fully interpreted.

See [vendor compatibility](VENDOR_COMPATIBILITY.md) for the 20 vendor families
covered by onboarding profiles and the supported mode for each.

## Listeners

- `protocol: netflow`, default UDP port 2055: automatically selects v1, v5,
  v7, v8, v9, or IPFIX using the packet version.
- `protocol: ipfix`, default UDP port 4739: IPFIX only.
- `protocol: sflow`, default UDP port 6343: sFlow v5 only.

Set `transport: tcp` or `transport: sctp` on an IPFIX listener to accept
RFC 7011 stream exports. SCTP sockets are available on Linux builds and use
IPv4 binds; TLS/DTLS termination remains outside the collector.

Existing configurations continue to work. NetFlow v1 and v7 do not require
new listeners. Exporter admission rules use the listener protocol names above.

## Fixed NetFlow records

NetFlow v1/v5/v7 decode IPv4 addresses, next hop, interfaces, counters,
ports, protocol, ToS/DSCP/ECN, TCP flags, and uptime-relative timestamps.
Version-specific behavior includes v1's different TCP flag offset, v5
sampling/engine metadata and AS/prefix information, and v7 router shortcut
and validity flags retained in `custom`. V1 has no sequence counter.
V7 validity flags are retained, not interpreted as field suppression rules.

## NetFlow v9 and IPFIX

Both protocols decode ordinary and options templates. Templates are isolated
by exporter IP, transport/source port, listener, protocol, observation domain,
and template ID. An exporter changing source port or stream connection must
send new templates.

Options records are available in the template snapshot API and never counted
as traffic flows. Up to 256 scope-specific option records are retained per
options template. Matching sampling/application metadata is applied to data
records, without replacing values explicitly present in those records.
V9 system/interface/template scopes and IPFIX observation-domain,
interface, application, and matching raw IE scopes are understood. Unknown
scopes are retained but not applied globally. Sampler/selector IDs must match
when present; arbitrary vendor sampling algorithms are not implemented.

IPFIX supports enterprise field namespaces, reduced-size counters,
short records, and variable-length fields (including extended lengths).
Unknown standard and enterprise fields are retained as hex values in
`custom`; retaining a field is not semantic support for it. Enterprise
fields cannot overwrite same-numbered standard fields.

RFC 5103 reverse counters (PEN 29305) are normalized as a second directional
flow without increasing the wire-record count used for sequence monitoring.
PAN-OS private v9 App-ID/User-ID fields are normalized when its namespace
is identified by IE 346. FortiGate application and sampler options are matched
independently. Standard IPv6 NAT, VRF, NAT-event, and firewall-event fields are
also handled.

Normalized information includes IPv4/IPv6 addresses, ports, counters,
interfaces, AS numbers, prefixes independent of template field order,
IPv6 next hop (IE 62), MAC/VLAN, application, NAT, and flow timestamps.
IPv6 flow label (IE 31) is retained as metadata, not mistaken for next hop.
Absolute second/millisecond/NTP timestamps, export-time deltas, and uptime
timestamps with a v9 header or IPFIX system initialization time are handled.
IPFIX uptime fields without an initialization time remain in metadata and
use export time as the normalized timestamp fallback.

Malformed framing, truncated fields, zero-byte records, and nonzero set
padding are rejected. Padding is distinguished from short records using
the template's minimum wire size. IPFIX template withdrawals received over
UDP are ignored as required by RFC 7011 section 8.4. Templates expire after
30 minutes in the collector.

Sequence monitoring uses record counts for fixed NetFlow/IPFIX (including
options records) and datagram counts for v9/sFlow, with transport/domain
isolation and uint32 rollover handling. Monitoring retains up to 4096 active
sequence streams; traffic collection continues beyond that limit.

## sFlow v5

Regular and expanded flow samples support sampled IPv4/IPv6 records and raw
Ethernet, IPv4, and IPv6 headers. Raw Ethernet decoding includes stacked
802.1Q/802.1ad VLAN tags and IP behind MPLS labels. IPv6 extension headers
are traversed; non-initial IPv4/IPv6 fragments do not create fictitious ports.

Sample rate, ingress/egress interface, source ID, sub-agent ID, sample pool,
drops, switch VLAN/priority, and router next hop/prefix metadata are retained.
Extended gateway records add AS numbers, AS paths, communities, and local
preference; extended NAT records add translated IPv4/IPv6 addresses.
One flow sample produces at most one traffic flow, even when multiple packet
representations are present. Each packet sample contributes one packet before
the collector applies sampling extrapolation. Unknown flow records are
retained as custom hex metadata when a supported packet record is present.

## Explicit limitations

- NetFlow v8 Cisco aggregation schemes 1--14 are decoded into normalized
  aggregate flows; uncommon undocumented schemes are rejected explicitly.
- IPFIX over TCP and SCTP is supported. TLS/DTLS-wrapped IPFIX requires a
  terminating proxy or load balancer in front of the collector.
- sFlow counter samples, discarded-packet samples, non-IP packet-only samples,
  and all extended record semantics are not normalized as traffic flows.
- IPFIX structured/list information elements and vendor enterprise schemas
  are retained as raw fields, not recursively or semantically decoded.
- Cisco Flexible NetFlow, Juniper J-Flow, Huawei NetStream, MikroTik Traffic
  Flow, cflowd-compatible exports, and IPFIX-based vendor products work only
  through the supported standard wire formats. Device/firmware compatibility
  requires representative exports; it has not been hardware-certified.
- Cloud flow-log files/APIs and proprietary non-NetFlow wire protocols are
  separate integrations and are not accepted by these UDP listeners.
- UDP delivery, exporter reboot detection, and every vendor-specific sequence
  or sampling behavior cannot be guaranteed.

## Validation and references

Regression tests exercise protocol versions, source-port/listener isolation,
options scope matching and refresh, short records, padding, enterprise field
collisions, variable-length fields, uptime rollover, single-count sFlow
samples, QinQ, IPv6 extensions, fragments, and truncated packets. These are
synthetic wire fixtures, not captured device certification traces.

- [Cisco NetFlow export formats](https://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html)
- [NetFlow v9: RFC 3954](https://www.rfc-editor.org/rfc/rfc3954)
- [IPFIX: RFC 7011](https://www.rfc-editor.org/rfc/rfc7011)
- [sFlow version 5](https://sflow.org/sflow_version_5.txt)
- [IANA IPFIX information elements](https://www.iana.org/assignments/ipfix)

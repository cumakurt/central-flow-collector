# Performance

v4 uses bounded listener and storage queues, batch UDP reads on Linux, framed
IPFIX stream readers, worker sharding, reusable buffers, async storage batches,
bounded analytics state and ClickHouse aggregate queries. TCP/SCTP stream
connections are framed by the IPFIX message length and are isolated per
connection; SCTP collection is available on Linux builds.

Two reproducible tools are shipped:

```bash
flowbench -target 127.0.0.1:2055 -flows-per-packet 30 -workers 4 -duration 30s
querybench -rows 50000 -iterations 5
```

`flowbench` reports packet/s, flow/s, MiB/s, UDP write p50/p95/p99, allocation and GC statistics. `querybench` exercises last-15m sources, last-24h destinations, seven-day trend, IP search, ASN/country/protocol aggregation and exporter statistics.

Never interpret sandbox benchmark numbers as certified production capacity. Validate target throughput on the actual CPU/NIC/kernel/ClickHouse topology and record listener drops, queue utilization, storage write errors and query percentiles.

## v4.0.0 release validation snapshot

The release sandbox smoke run used 2 UDP writers, 30 flows per NetFlow v5 datagram and a 2,000 packet/s target for three seconds. It produced 111,780 decoded flows with zero sender errors, zero listener drops, zero storage drops and zero storage write errors. The observed sender rate was about 37.3k flows/s; this is a correctness smoke/load result, not a capacity ceiling.

On the release host (Intel Xeon Platinum 8370C), `BenchmarkDecodeV5_30Flows` measured 18.711 µs/op, 38,416 B/op and 96 allocs/op. The local 50k-row query benchmark measured p95 values of 43.64 ms (15m top sources), 147.82 ms (24h top destinations), 803.80 ms (7d trend) and 436.71 ms (IP search). See `VALIDATION_REPORT_4.0.0.md` and `validation/` for the exact logs.

## 2026-09-16 capacity validation

A full all-protocol capacity exercise and performance hardening pass is documented in [`../PERFORMANCE_CAPACITY_REPORT_2026-09-16.md`](../PERFORMANCE_CAPACITY_REPORT_2026-09-16.md).

`flowbench` now supports all ingestion protocols:

```bash
flowbench -protocol netflow5 -target 127.0.0.1:2055 -flows-per-packet 30 -workers 4 -pps 7000 -duration 30s
flowbench -protocol netflow9 -target 127.0.0.1:2055 -flows-per-packet 30 -workers 4 -pps 7000 -duration 30s
flowbench -protocol ipfix    -target 127.0.0.1:4739 -flows-per-packet 30 -workers 4 -pps 7000 -duration 30s
flowbench -protocol sflow    -target 127.0.0.1:6343 -flows-per-packet 30 -workers 4 -pps 7000 -duration 30s
```

On the 5-vCPU AMD EPYC sandbox with the local backend and production analytics/dedup paths enabled, the common zero-drop dense-flow result was about 205–210k flow/s. Use <=140k flow/s as a conservative design target on that measured node class; re-certify on production hardware. Local JSONL consumes about 451 bytes/flow in the measured fixture and is not recommended for sustained high-rate multi-day retention.

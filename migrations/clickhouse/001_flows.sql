-- Reference ClickHouse schema. The Go backend creates this table automatically.
CREATE DATABASE IF NOT EXISTS flowcollector;
CREATE TABLE IF NOT EXISTS flowcollector.flows (
  receive_time DateTime64(3, 'UTC'), start_time Nullable(DateTime64(3, 'UTC')), end_time Nullable(DateTime64(3, 'UTC')),
  collector_node LowCardinality(String),
  exporter String, listener LowCardinality(String), flow_protocol LowCardinality(String), observation_domain UInt32,
  src_ip String, dst_ip String, src_port UInt16, dst_port UInt16, ip_protocol UInt8, packets UInt64, bytes UInt64,
  tcp_flags UInt16, tos UInt8, dscp UInt8, ecn UInt8, ingress_if UInt32, egress_if UInt32, next_hop String,
  src_as UInt32, dst_as UInt32, src_prefix String, dst_prefix String, vlan UInt16, src_mac String, dst_mac String,
  nat_src_ip String, nat_dst_ip String, nat_src_port UInt16, nat_dst_port UInt16, direction UInt8, sampling_rate UInt32,
  sequence UInt32, application_id String, application_name String, vrf String, custom_json String
) ENGINE = MergeTree
PARTITION BY toYYYYMM(receive_time)
ORDER BY (toStartOfHour(receive_time), exporter, src_ip, dst_ip, ip_protocol, dst_port)
TTL receive_time + INTERVAL 7 DAY
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1;

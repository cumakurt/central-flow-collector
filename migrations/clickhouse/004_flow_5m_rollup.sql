-- v3.0.0: scalable five-minute rollup for dashboard/top-N workloads.
CREATE TABLE IF NOT EXISTS flowcollector.flows_5m (
  bucket DateTime('UTC'), tenant LowCardinality(String), src_ip String, dst_ip String,
  ip_protocol UInt8, dst_port UInt16, src_country LowCardinality(String), dst_country LowCardinality(String),
  bytes UInt64, packets UInt64, flows UInt64
) ENGINE = SummingMergeTree((bytes, packets, flows))
PARTITION BY toYYYYMM(bucket)
ORDER BY (bucket, tenant, src_ip, dst_ip, ip_protocol, dst_port);

CREATE MATERIALIZED VIEW IF NOT EXISTS flowcollector.flows_5m_mv TO flowcollector.flows_5m AS
SELECT toStartOfFiveMinutes(receive_time) AS bucket, tenant, src_ip, dst_ip, ip_protocol, dst_port,
       src_country, dst_country, sum(bytes) AS bytes, sum(packets) AS packets, count() AS flows
FROM flowcollector.flows
GROUP BY bucket, tenant, src_ip, dst_ip, ip_protocol, dst_port, src_country, dst_country;

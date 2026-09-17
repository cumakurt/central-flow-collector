-- v1.4.0 additive collector-node identity for shared ClickHouse deployments.
ALTER TABLE flowcollector.flows ADD COLUMN IF NOT EXISTS collector_node LowCardinality(String);

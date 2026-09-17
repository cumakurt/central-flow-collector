-- v1.2.0 additive enrichment columns. The application also executes these
-- migrations with ADD COLUMN IF NOT EXISTS during ClickHouse bootstrap.
ALTER TABLE flowcollector.flows ADD COLUMN IF NOT EXISTS src_as_name String;
ALTER TABLE flowcollector.flows ADD COLUMN IF NOT EXISTS dst_as_name String;
ALTER TABLE flowcollector.flows ADD COLUMN IF NOT EXISTS src_country LowCardinality(String);
ALTER TABLE flowcollector.flows ADD COLUMN IF NOT EXISTS dst_country LowCardinality(String);
ALTER TABLE flowcollector.flows ADD COLUMN IF NOT EXISTS src_site LowCardinality(String);
ALTER TABLE flowcollector.flows ADD COLUMN IF NOT EXISTS dst_site LowCardinality(String);

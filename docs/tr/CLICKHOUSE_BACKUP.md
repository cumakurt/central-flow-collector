# ClickHouse yedekleme

Kaynak: [CLICKHOUSE_BACKUP.md](../CLICKHOUSE_BACKUP.md)

ClickHouse akışları JSONL gzip arşivine aktarılabilir, doğrulanabilir ve
collector tarafından güvenli restore edilebilir. Büyük kurulumlarda retention,
spool/WAL, sorgu süresi, shard/replica ve Distributed tablo ayarlarını birlikte
planlayın.

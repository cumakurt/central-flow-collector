# Backup, Restore and DR — v1.5.0

`flowcollector backup create` produces a gzip-compressed tar archive with `manifest.json`. Every archived file has a SHA256 digest, original size and mode. Backup creation and verification are streaming and do not require loading raw flow files into memory.

By default the backup includes the active config and persistent application metadata under the data directory, but excludes `flows/` and the temporary bootstrap password file. `--include-flows` explicitly includes local JSONL flow files. ClickHouse table data is **not** copied by this CLI; use native ClickHouse backup/replication tooling for production ClickHouse data.

`flowcollector backup verify` streams every archive entry and checks it against the manifest. `restore` refuses to run without `--force`, rejects path traversal, verifies the complete archive before extraction, writes through temporary files, and applies the existing data-directory UID/GID to restored persistent data.

Stop the service before restore. After restore run `flowcollector repair check`, start the service, then verify `/ready`.

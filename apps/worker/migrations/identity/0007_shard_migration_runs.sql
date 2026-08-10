CREATE TABLE shard_migration_runs (
  id TEXT PRIMARY KEY,
  domain TEXT NOT NULL CHECK(domain IN ('social','guild')),
  bucket INTEGER NOT NULL,
  source_binding TEXT NOT NULL,
  target_binding TEXT NOT NULL,
  generation INTEGER NOT NULL,
  requested_by TEXT NOT NULL,
  phase TEXT NOT NULL,
  copied_rows INTEGER NOT NULL DEFAULT 0,
  error TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;

CREATE INDEX shard_migration_active_idx
  ON shard_migration_runs(domain,bucket,phase,updated_at);

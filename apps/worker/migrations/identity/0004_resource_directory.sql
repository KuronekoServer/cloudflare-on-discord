CREATE TABLE resource_directory (
  resource_id TEXT PRIMARY KEY,
  resource_type TEXT NOT NULL CHECK(resource_type IN ('guild_channel','conversation','dm_channel')),
  owner_id TEXT NOT NULL,
  created_at TEXT NOT NULL
) STRICT;

CREATE INDEX resource_directory_owner_idx
  ON resource_directory(resource_type, owner_id);

CREATE TABLE queue_receipts (
  event_id TEXT PRIMARY KEY,
  topic TEXT NOT NULL,
  processed_at TEXT NOT NULL
) STRICT;

CREATE INDEX queue_receipts_processed_idx ON queue_receipts(processed_at);

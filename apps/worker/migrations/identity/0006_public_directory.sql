CREATE TABLE invite_directory (
  code TEXT PRIMARY KEY,
  guild_id TEXT NOT NULL,
  channel_id TEXT NOT NULL,
  created_at TEXT NOT NULL
) STRICT;

CREATE INDEX invite_directory_guild_idx ON invite_directory(guild_id);

CREATE TABLE guild_directory (
  guild_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT,
  enabled INTEGER NOT NULL DEFAULT 0,
  member_count INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL
) STRICT;

CREATE INDEX guild_directory_public_idx
  ON guild_directory(enabled, member_count DESC, updated_at DESC);

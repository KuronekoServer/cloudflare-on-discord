CREATE TABLE stage_instances (
  channel_id TEXT PRIMARY KEY,
  guild_id TEXT NOT NULL,
  topic TEXT NOT NULL,
  privacy_level INTEGER NOT NULL DEFAULT 2,
  discoverable_disabled INTEGER NOT NULL DEFAULT 1,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE thread_members (
  channel_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  joined_at TEXT NOT NULL,
  flags INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(channel_id,user_id)
) STRICT;

CREATE INDEX thread_members_user_idx ON thread_members(user_id,joined_at);

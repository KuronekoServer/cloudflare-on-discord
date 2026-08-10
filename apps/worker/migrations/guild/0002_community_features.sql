CREATE TABLE bans (
  guild_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  moderator_id TEXT NOT NULL,
  reason TEXT NOT NULL,
  expires_at TEXT,
  created_at TEXT NOT NULL,
  PRIMARY KEY(guild_id, user_id)
) STRICT;

CREATE INDEX bans_expiry_idx ON bans(expires_at);

CREATE TABLE automod_rules (
  id TEXT PRIMARY KEY,
  guild_id TEXT NOT NULL,
  name TEXT NOT NULL,
  trigger_type TEXT NOT NULL CHECK(trigger_type IN ('keyword','regex')),
  trigger_metadata TEXT NOT NULL,
  action_type TEXT NOT NULL CHECK(action_type IN ('block','flag')),
  enabled INTEGER NOT NULL DEFAULT 1,
  creator_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;

CREATE INDEX automod_rules_guild_idx ON automod_rules(guild_id, enabled);

CREATE TABLE thread_metadata (
  channel_id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL,
  archived INTEGER NOT NULL DEFAULT 0,
  locked INTEGER NOT NULL DEFAULT 0,
  auto_archive_minutes INTEGER NOT NULL DEFAULT 1440,
  created_at TEXT NOT NULL,
  archived_at TEXT
) STRICT;

CREATE TABLE forum_tags (
  id TEXT PRIMARY KEY,
  channel_id TEXT NOT NULL,
  name TEXT NOT NULL,
  emoji TEXT,
  moderated INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE TABLE forum_post_tags (
  channel_id TEXT NOT NULL,
  tag_id TEXT NOT NULL,
  PRIMARY KEY(channel_id, tag_id)
) STRICT;

CREATE TABLE guild_emojis (
  id TEXT PRIMARY KEY,
  guild_id TEXT NOT NULL,
  name TEXT NOT NULL,
  object_key TEXT NOT NULL,
  creator_id TEXT NOT NULL,
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE guild_stickers (
  id TEXT PRIMARY KEY,
  guild_id TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT,
  object_key TEXT NOT NULL,
  creator_id TEXT NOT NULL,
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE soundboard_sounds (
  id TEXT PRIMARY KEY,
  guild_id TEXT NOT NULL,
  name TEXT NOT NULL,
  object_key TEXT NOT NULL,
  volume REAL NOT NULL DEFAULT 1.0,
  creator_id TEXT NOT NULL,
  created_at TEXT NOT NULL
) STRICT;

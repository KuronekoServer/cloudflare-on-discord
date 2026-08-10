PRAGMA foreign_keys = ON;

CREATE TABLE guilds (
  id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT,
  icon_key TEXT,
  features TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE roles (
  id TEXT PRIMARY KEY,
  guild_id TEXT NOT NULL REFERENCES guilds(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  permissions TEXT NOT NULL DEFAULT '0',
  position INTEGER NOT NULL,
  color INTEGER NOT NULL DEFAULT 0,
  managed INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE members (
  guild_id TEXT NOT NULL REFERENCES guilds(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL,
  nickname TEXT,
  role_ids TEXT NOT NULL DEFAULT '[]',
  timeout_until TEXT,
  joined_at TEXT NOT NULL,
  PRIMARY KEY (guild_id, user_id)
) STRICT;
CREATE INDEX members_user_idx ON members(user_id, guild_id);

CREATE TABLE channels (
  id TEXT PRIMARY KEY,
  guild_id TEXT NOT NULL REFERENCES guilds(id) ON DELETE CASCADE,
  parent_id TEXT,
  type TEXT NOT NULL,
  name TEXT NOT NULL,
  topic TEXT,
  position INTEGER NOT NULL,
  slowmode_seconds INTEGER NOT NULL DEFAULT 0,
  last_message_id TEXT,
  created_at TEXT NOT NULL
) STRICT;
CREATE INDEX channels_guild_idx ON channels(guild_id, position);

CREATE TABLE permission_overwrites (
  channel_id TEXT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
  target_id TEXT NOT NULL,
  target_type TEXT NOT NULL CHECK(target_type IN ('role','member')),
  allow_bits TEXT NOT NULL DEFAULT '0',
  deny_bits TEXT NOT NULL DEFAULT '0',
  PRIMARY KEY (channel_id, target_id)
) STRICT;

CREATE TABLE invites (
  code TEXT PRIMARY KEY,
  guild_id TEXT NOT NULL REFERENCES guilds(id) ON DELETE CASCADE,
  channel_id TEXT NOT NULL,
  creator_id TEXT NOT NULL,
  max_uses INTEGER,
  uses INTEGER NOT NULL DEFAULT 0,
  expires_at TEXT,
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE scheduled_events (
  id TEXT PRIMARY KEY,
  guild_id TEXT NOT NULL REFERENCES guilds(id) ON DELETE CASCADE,
  channel_id TEXT,
  creator_id TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT,
  starts_at TEXT NOT NULL,
  ends_at TEXT,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE guild_audit (
  id TEXT PRIMARY KEY,
  guild_id TEXT NOT NULL,
  actor_id TEXT NOT NULL,
  action TEXT NOT NULL,
  target_id TEXT,
  reason TEXT,
  changes TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL
) STRICT;
CREATE INDEX guild_audit_idx ON guild_audit(guild_id, created_at DESC);

CREATE TABLE reports (
  id TEXT PRIMARY KEY,
  guild_id TEXT,
  reporter_id TEXT NOT NULL,
  target_type TEXT NOT NULL,
  target_id TEXT NOT NULL,
  reason TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',
  created_at TEXT NOT NULL,
  resolved_at TEXT
) STRICT;

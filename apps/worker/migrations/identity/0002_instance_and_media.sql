CREATE TABLE IF NOT EXISTS instance_admins (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  granted_by TEXT NOT NULL,
  granted_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS instance_config (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS media_objects (
  id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL REFERENCES users(id),
  guild_id TEXT,
  object_key TEXT NOT NULL UNIQUE,
  filename TEXT NOT NULL,
  content_type TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  state TEXT NOT NULL DEFAULT 'pending',
  created_at TEXT NOT NULL,
  expires_at TEXT
) STRICT;
CREATE INDEX IF NOT EXISTS media_quota_user_idx ON media_objects(owner_id, created_at, state);
CREATE INDEX IF NOT EXISTS media_quota_guild_idx ON media_objects(guild_id, state);

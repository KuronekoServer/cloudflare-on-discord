CREATE TABLE bot_guild_installs (
  application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  guild_id TEXT NOT NULL,
  bot_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  permissions TEXT NOT NULL DEFAULT '0',
  installed_by TEXT NOT NULL,
  installed_at TEXT NOT NULL,
  PRIMARY KEY(application_id,guild_id)
) STRICT;

CREATE INDEX bot_guild_dispatch_idx
  ON bot_guild_installs(guild_id,bot_user_id);

CREATE TABLE application_commands (
  id TEXT PRIMARY KEY,
  application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  guild_id TEXT,
  type INTEGER NOT NULL DEFAULT 1,
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  payload_json TEXT NOT NULL,
  version TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(application_id,guild_id,type,name)
) STRICT;

CREATE TABLE webhooks (
  id TEXT PRIMARY KEY,
  application_id TEXT REFERENCES applications(id) ON DELETE SET NULL,
  guild_id TEXT,
  channel_id TEXT NOT NULL,
  creator_id TEXT NOT NULL,
  name TEXT NOT NULL,
  avatar_key TEXT,
  token_hash TEXT NOT NULL UNIQUE,
  token_ciphertext TEXT NOT NULL,
  created_at TEXT NOT NULL
) STRICT;

CREATE INDEX webhooks_channel_idx ON webhooks(channel_id,created_at);

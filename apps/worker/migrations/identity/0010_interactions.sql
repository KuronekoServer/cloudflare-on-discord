CREATE TABLE interaction_tokens (
  id TEXT PRIMARY KEY,
  token_hash TEXT NOT NULL UNIQUE,
  application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  bot_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  guild_id TEXT,
  channel_id TEXT NOT NULL,
  interaction_type INTEGER NOT NULL,
  request_json TEXT NOT NULL,
  response_type INTEGER,
  response_json TEXT,
  state TEXT NOT NULL DEFAULT 'pending',
  expires_at TEXT NOT NULL,
  responded_at TEXT,
  created_at TEXT NOT NULL
) STRICT;

CREATE INDEX interaction_user_idx
  ON interaction_tokens(user_id,created_at DESC);

CREATE INDEX interaction_expiry_idx
  ON interaction_tokens(expires_at,state);

PRAGMA foreign_keys = ON;

CREATE TABLE users (
  id TEXT PRIMARY KEY,
  email_ciphertext TEXT NOT NULL UNIQUE,
  email_lookup_hash TEXT NOT NULL UNIQUE,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  display_name TEXT NOT NULL,
  avatar_key TEXT,
  status TEXT NOT NULL DEFAULT 'pending_email',
  locale TEXT NOT NULL DEFAULT 'ja',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE password_credentials (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  password_hash TEXT NOT NULL,
  totp_secret_ciphertext TEXT NOT NULL,
  totp_last_counter INTEGER,
  changed_at TEXT NOT NULL
) STRICT;

CREATE TABLE passkeys (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  credential_id TEXT NOT NULL UNIQUE,
  public_key BLOB NOT NULL,
  counter INTEGER NOT NULL DEFAULT 0,
  transports TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL,
  last_used_at TEXT
) STRICT;

CREATE TABLE auth_challenges (
  id TEXT PRIMARY KEY,
  user_id TEXT,
  kind TEXT NOT NULL,
  challenge_hash TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  consumed_at TEXT
) STRICT;

CREATE TABLE sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  family_id TEXT NOT NULL,
  refresh_hash TEXT NOT NULL UNIQUE,
  previous_refresh_hash TEXT,
  user_agent TEXT,
  ip_hmac TEXT,
  expires_at TEXT NOT NULL,
  revoked_at TEXT,
  created_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL
) STRICT;
CREATE INDEX sessions_user_idx ON sessions(user_id, revoked_at);

CREATE TABLE one_time_tokens (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at TEXT NOT NULL,
  consumed_at TEXT
) STRICT;

CREATE TABLE recovery_codes (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash TEXT NOT NULL,
  consumed_at TEXT,
  PRIMARY KEY (user_id, code_hash)
) STRICT;

CREATE TABLE applications (
  id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL REFERENCES users(id),
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  redirect_uris TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE bots (
  application_id TEXT PRIMARY KEY REFERENCES applications(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL UNIQUE REFERENCES users(id),
  token_hash TEXT NOT NULL,
  public_key TEXT NOT NULL,
  intents TEXT NOT NULL DEFAULT '0',
  enabled INTEGER NOT NULL DEFAULT 1
) STRICT;

CREATE TABLE shard_map (
  domain TEXT NOT NULL,
  bucket INTEGER NOT NULL,
  generation INTEGER NOT NULL,
  binding_name TEXT NOT NULL,
  read_binding_name TEXT,
  state TEXT NOT NULL DEFAULT 'active',
  updated_at TEXT NOT NULL,
  PRIMARY KEY (domain, bucket, generation)
) STRICT;

CREATE TABLE idempotency_keys (
  actor_id TEXT NOT NULL,
  operation TEXT NOT NULL,
  key TEXT NOT NULL,
  response_json TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  PRIMARY KEY (actor_id, operation, key)
) STRICT;

CREATE TABLE transactional_outbox (
  id TEXT PRIMARY KEY,
  topic TEXT NOT NULL,
  partition_key TEXT NOT NULL,
  payload TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  available_at TEXT NOT NULL,
  delivered_at TEXT
) STRICT;
CREATE INDEX outbox_pending_idx ON transactional_outbox(delivered_at, available_at);

CREATE TABLE admin_audit (
  id TEXT PRIMARY KEY,
  actor_id TEXT NOT NULL,
  action TEXT NOT NULL,
  target_id TEXT,
  reason TEXT NOT NULL,
  metadata TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE instance_admins (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  granted_by TEXT NOT NULL,
  granted_at TEXT NOT NULL
) STRICT;

CREATE TABLE instance_config (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE media_objects (
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
CREATE INDEX media_quota_user_idx ON media_objects(owner_id, created_at, state);
CREATE INDEX media_quota_guild_idx ON media_objects(guild_id, state);

INSERT INTO shard_map(domain, bucket, generation, binding_name, updated_at)
VALUES ('social', 0, 1, 'SOCIAL_DB_00', datetime('now')),
       ('guild', 0, 1, 'GUILD_DB_00', datetime('now'));

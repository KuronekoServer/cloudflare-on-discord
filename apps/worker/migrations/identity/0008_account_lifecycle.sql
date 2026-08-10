CREATE TABLE account_lifecycle_jobs (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK(kind IN ('export','delete')),
  phase TEXT NOT NULL,
  object_key TEXT,
  error TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;

CREATE INDEX account_lifecycle_user_idx
  ON account_lifecycle_jobs(user_id,kind,created_at DESC);

CREATE TABLE user_channel_activity (
  user_id TEXT NOT NULL,
  channel_id TEXT NOT NULL,
  partition_key TEXT NOT NULL,
  last_message_at TEXT NOT NULL,
  PRIMARY KEY(user_id,channel_id)
) STRICT;

CREATE INDEX user_channel_activity_channel_idx
  ON user_channel_activity(channel_id,user_id);

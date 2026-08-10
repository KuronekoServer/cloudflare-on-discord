CREATE TABLE guild_membership_index (
  user_id TEXT NOT NULL,
  guild_id TEXT NOT NULL,
  joined_at TEXT NOT NULL,
  PRIMARY KEY (user_id, guild_id)
) STRICT;

CREATE INDEX guild_membership_by_user
  ON guild_membership_index(user_id, joined_at);

CREATE TABLE conversation_membership_index (
  user_id TEXT NOT NULL,
  conversation_id TEXT NOT NULL,
  channel_id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK(kind IN ('dm','group_dm')),
  name TEXT,
  owner_id TEXT,
  joined_at TEXT NOT NULL,
  PRIMARY KEY (user_id, conversation_id)
) STRICT;

CREATE UNIQUE INDEX conversation_channel_by_user
  ON conversation_membership_index(user_id, channel_id);

PRAGMA foreign_keys = ON;

CREATE TABLE relationships (
  user_id TEXT NOT NULL,
  target_user_id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK(kind IN ('friend_pending_outgoing','friend_pending_incoming','friend','blocked')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (user_id, target_user_id)
) STRICT;

CREATE TABLE conversations (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK(kind IN ('dm','group_dm')),
  name TEXT,
  owner_id TEXT,
  channel_id TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE conversation_members (
  conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL,
  joined_at TEXT NOT NULL,
  last_read_message_id TEXT,
  notifications TEXT NOT NULL DEFAULT 'all',
  PRIMARY KEY (conversation_id, user_id)
) STRICT;
CREATE INDEX conversations_by_member ON conversation_members(user_id, joined_at);

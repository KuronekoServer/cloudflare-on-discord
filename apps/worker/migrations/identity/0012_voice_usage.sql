CREATE TABLE voice_usage (
  id TEXT PRIMARY KEY,
  channel_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  session_id TEXT,
  started_at TEXT NOT NULL,
  ended_at TEXT NOT NULL,
  duration_seconds INTEGER NOT NULL,
  audio_track_seconds INTEGER NOT NULL DEFAULT 0,
  camera_track_seconds INTEGER NOT NULL DEFAULT 0,
  screen_track_seconds INTEGER NOT NULL DEFAULT 0,
  estimated_source_bytes INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE INDEX voice_usage_time_idx ON voice_usage(ended_at);
CREATE INDEX voice_usage_channel_idx ON voice_usage(channel_id,ended_at);

WITH RECURSIVE social_buckets(bucket) AS (
  SELECT 0
  UNION ALL
  SELECT bucket + 1 FROM social_buckets WHERE bucket < 15
)
INSERT OR REPLACE INTO shard_map(domain,bucket,generation,binding_name,read_binding_name,state,updated_at)
SELECT 'social',bucket,1,printf('SOCIAL_DB_%02d',bucket),NULL,'active',datetime('now') FROM social_buckets;

WITH RECURSIVE guild_buckets(bucket) AS (
  SELECT 0
  UNION ALL
  SELECT bucket + 1 FROM guild_buckets WHERE bucket < 31
)
INSERT OR REPLACE INTO shard_map(domain,bucket,generation,binding_name,read_binding_name,state,updated_at)
SELECT 'guild',bucket,1,printf('GUILD_DB_%02d',bucket),NULL,'active',datetime('now') FROM guild_buckets;

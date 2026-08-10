export interface RuntimeVars {
  ENVIRONMENT: "dev" | "staging" | "prod";
  APP_NAME: string;
  PUBLIC_ORIGIN: string;
  RP_ID: string;
  EMAIL_FROM: string;
  ACCESS_TOKEN_TTL_SECONDS: string;
  REFRESH_TOKEN_TTL_SECONDS: string;
  UPLOAD_FILE_LIMIT_BYTES: string;
  UPLOAD_DAILY_USER_LIMIT_BYTES: string;
  UPLOAD_GUILD_LIMIT_BYTES: string;
  VOICE_ROOM_LIMIT: string;
  VOICE_SCREEN_SHARE_LIMIT: string;
  JWT_SIGNING_KEY?: string;
  DATA_ENCRYPTION_KEY?: string;
  LOOKUP_HMAC_KEY?: string;
  TURNSTILE_SECRET?: string;
  TURNSTILE_BYPASS_TOKEN?: string;
  ADMIN_BOOTSTRAP_TOKEN?: string;
  REALTIME_APP_ID?: string;
  REALTIME_API_TOKEN?: string;
  CLOUDFLARE_ACCOUNT_ID?: string;
  CLOUDFLARE_BACKUP_API_TOKEN?: string;
}

export interface Env extends RuntimeVars {
  IDENTITY_DB: D1Database;
  SOCIAL_DB_00: D1Database;
  GUILD_DB_00: D1Database;
  PUBLIC_CACHE: KVNamespace;
  MEDIA: R2Bucket;
  RELEASES: R2Bucket;
  EVENT_QUEUE: Queue<QueueEvent>;
  EMAIL: SendEmail;
  ASSETS: Fetcher;
  ID_GENERATORS: DurableObjectNamespace;
  GUILD_COORDINATORS: DurableObjectNamespace;
  GUILD_PRESENCE: DurableObjectNamespace;
  CHANNEL_HUBS: DurableObjectNamespace;
  MESSAGE_PARTITIONS: DurableObjectNamespace;
  SEARCH_PARTITIONS: DurableObjectNamespace;
  USER_SESSIONS: DurableObjectNamespace;
  VOICE_ROOMS: DurableObjectNamespace;
  BOT_GATEWAY_SHARDS: DurableObjectNamespace;
  SHARD_MIGRATION: Workflow<
    import("./workflows/shard-migration").ShardMigrationParams
  >;
  ACCOUNT_LIFECYCLE: Workflow<
    import("./workflows/account-lifecycle").AccountLifecycleParams
  >;
  BACKUP_WORKFLOW: Workflow<import("./workflows/backup").BackupWorkflowParams>;
  JWT_SIGNING_KEY_SECRET?: SecretsStoreSecret;
  DATA_ENCRYPTION_KEY_SECRET?: SecretsStoreSecret;
  LOOKUP_HMAC_KEY_SECRET?: SecretsStoreSecret;
  TURNSTILE_SECRET_SECRET?: SecretsStoreSecret;
  TURNSTILE_BYPASS_TOKEN_SECRET?: SecretsStoreSecret;
  ADMIN_BOOTSTRAP_TOKEN_SECRET?: SecretsStoreSecret;
  REALTIME_API_TOKEN_SECRET?: SecretsStoreSecret;
  CLOUDFLARE_BACKUP_API_TOKEN_SECRET?: SecretsStoreSecret;
}

export interface QueueEvent {
  id: string;
  topic:
    | "email"
    | "message.archive"
    | "search.index"
    | "search.delete"
    | "bot.dispatch"
    | "audit"
    | "voice.usage"
    | "object.delete";
  partitionKey: string;
  payload: Record<string, unknown>;
}

export interface AuthUser {
  id: string;
  sessionId: string;
  username: string;
  displayName: string;
}

export type AppVariables = {
  traceId: string;
  auth: AuthUser;
};

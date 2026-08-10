export function openApi(origin: string) {
  return {
    openapi: "3.1.0",
    info: {
      title: "CloudCord first-party API",
      version: "0.1.0",
      license: { name: "AGPL-3.0-or-later" },
    },
    servers: [{ url: `${origin}/api/v1` }],
    security: [{ bearerAuth: [] }],
    paths: {
      "/auth/register": { post: operation("Register an account", false) },
      "/auth/verify-email": {
        post: operation("Verify an email address", false),
      },
      "/auth/login": { post: operation("Password and TOTP login", false) },
      "/auth/passkey/options": {
        post: operation("Begin passkey login", false),
      },
      "/auth/passkey/verify": {
        post: operation("Finish passkey login", false),
      },
      "/auth/refresh": { post: operation("Rotate a refresh token", false) },
      "/auth/desktop/token": {
        post: operation("Exchange a one-time desktop PKCE code", false),
      },
      "/auth/desktop/authorize": {
        post: operation("Authorize a desktop PKCE deep link", true, true),
      },
      "/auth/logout": { post: operation("Revoke the current session") },
      "/auth/recovery/request": {
        post: operation("Request account recovery", false),
      },
      "/auth/recovery/complete": {
        post: operation("Complete account recovery", false),
      },
      "/directory": {
        get: operation("List discoverable guilds", false),
      },
      "/invites/{code}/preview": {
        get: operation("Preview a public invite", false),
      },
      "/invites/{code}": {
        post: operation("Join a guild using an invite", true, true),
      },
      "/me": { get: operation("Get the current user") },
      "/me/export": {
        post: operation("Start an account data export", true, true),
      },
      "/me/delete/passkey-options": {
        post: operation(
          "Begin passkey reauthentication for account deletion",
          true,
          true,
        ),
      },
      "/me/delete": {
        post: operation("Permanently delete the current account", true, true),
      },
      "/me/lifecycle/{jobId}": {
        get: operation("Read account lifecycle job status"),
      },
      "/me/lifecycle/{jobId}/file": {
        get: operation("Download an account export file"),
      },
      "/ws-ticket": {
        post: operation("Create a one-time WebSocket ticket", true, true),
      },
      "/passkeys/options": {
        post: operation("Begin adding a passkey", true, true),
      },
      "/passkeys/verify": {
        post: operation("Finish adding a passkey", true, true),
      },
      "/users/search": { get: operation("Search users by exact handle") },
      "/relationships": { get: operation("List relationships") },
      "/friend-requests": {
        post: operation("Create a friend request", true, true),
      },
      "/friend-requests/{userId}/accept": {
        post: operation("Accept a friend request", true, true),
      },
      "/blocks/{userId}": {
        put: operation("Block a user", true, true),
      },
      "/conversations": {
        get: operation("List DM conversations"),
        post: operation("Create a DM or group DM", true, true),
      },
      "/guilds": {
        get: operation("List guilds"),
        post: operation("Create a guild", true, true),
      },
      "/guilds/{guildId}/channels": {
        get: operation("List channels"),
        post: operation("Create a channel", true, true),
      },
      "/guilds/{guildId}/channels/{channelId}": {
        patch: operation("Update channel settings and slowmode", true, true),
      },
      "/guilds/{guildId}/invites": {
        post: operation("Create a guild invite", true, true),
      },
      "/guilds/{guildId}/directory": {
        patch: operation("Update public directory visibility", true, true),
      },
      "/guilds/{guildId}/members": {
        get: operation("List guild members"),
      },
      "/guilds/{guildId}/members/{userId}": {
        delete: operation("Kick a guild member", true, true),
      },
      "/guilds/{guildId}/members/{userId}/timeout": {
        patch: operation("Set or clear a member timeout", true, true),
      },
      "/guilds/{guildId}/bans/{userId}": {
        put: operation("Ban a user", true, true),
        delete: operation("Remove a ban", true, true),
      },
      "/guilds/{guildId}/audit": {
        get: operation("Read the guild audit log"),
      },
      "/guilds/{guildId}/automod": {
        get: operation("List AutoMod rules"),
        post: operation("Create an AutoMod keyword rule", true, true),
      },
      "/guilds/{guildId}/automod/{ruleId}": {
        delete: operation("Delete an AutoMod rule", true, true),
      },
      "/guilds/{guildId}/reports": {
        get: operation("List moderation reports"),
      },
      "/guilds/{guildId}/reports/{reportId}": {
        patch: operation("Resolve a moderation report", true, true),
      },
      "/guilds/{guildId}/search": {
        get: operation("Search the latest twelve monthly message partitions"),
      },
      "/reports": {
        post: operation("Create a moderation report", true, true),
      },
      "/admin/bootstrap": {
        post: operation("Bootstrap the first administrator", true, true),
      },
      "/admin/overview": { get: operation("Read operator metrics") },
      "/admin/settings": {
        patch: operation("Update instance settings", true, true),
      },
      "/admin/shards/migrations": {
        post: operation("Start a safe D1 shard migration", true, true),
      },
      "/admin/shards/migrations/{runId}": {
        get: operation("Read shard migration status"),
      },
      "/admin/shards/migrations/{runId}/abort": {
        post: operation(
          "Abort a shard migration and restore its source",
          true,
          true,
        ),
      },
      "/guilds/{guildId}/roles": {
        get: operation("List roles"),
        post: operation("Create a role", true, true),
      },
      "/guilds/{guildId}/members/{userId}/roles": {
        put: operation("Replace a member's roles", true, true),
      },
      "/channels/{channelId}/permissions/{targetId}": {
        put: operation("Set a channel permission overwrite", true, true),
      },
      "/channels/{channelId}/threads": {
        post: operation(
          "Create a public, private, forum, or announcement thread",
          true,
          true,
        ),
      },
      "/guilds/{guildId}/events": {
        get: operation("List scheduled events"),
        post: operation("Create a scheduled event", true, true),
      },
      "/channels/{channelId}/messages": {
        get: operation("Read ordered messages"),
        post: operation("Create a message", true, true),
      },
      "/channels/{channelId}/messages/{messageId}": {
        patch: operation("Edit a message", true, true),
        delete: operation("Delete a message", true, true),
      },
      "/channels/{channelId}/messages/{messageId}/reactions/{emoji}": {
        put: operation("Add the current user's reaction", true, true),
        delete: operation("Remove the current user's reaction", true, true),
      },
      "/channels/{channelId}/pins/{messageId}": {
        put: operation("Pin a message", true, true),
        delete: operation("Unpin a message", true, true),
      },
      "/channels/{channelId}/polls/{messageId}/answers/{answerId}": {
        put: operation("Vote for a poll answer", true, true),
        delete: operation("Remove a poll vote", true, true),
      },
      "/voice/{channelId}/join": {
        post: operation("Join live voice state", true, true),
      },
      "/voice/{channelId}": {
        delete: operation("Leave live voice state", true, true),
      },
      "/realtime/sessions": {
        post: operation("Create a Cloudflare Realtime session", true, true),
      },
      "/realtime/sessions/{sessionId}/tracks": {
        post: operation("Publish or subscribe to live tracks", true, true),
        delete: operation("Close live tracks", true, true),
      },
      "/realtime/sessions/{sessionId}/renegotiate": {
        put: operation("Renegotiate a live Realtime session", true, true),
      },
      "/uploads": {
        post: operation("Authorize an R2 upload", true, true),
      },
      "/applications": {
        get: operation("List Bot applications"),
        post: operation("Create a Bot application", true, true),
      },
      "/oauth2/authorize": {
        get: operation("Inspect and approve an OAuth2-style Bot install"),
      },
      "/guilds/{guildId}/bots/{applicationId}": {
        post: operation("Install a Bot application", true, true),
      },
      "/interactions": {
        post: operation("Dispatch an application interaction", true, true),
      },
      "/interactions/{interactionId}": {
        get: operation("Poll an interaction response"),
      },
    },
    components: {
      securitySchemes: {
        bearerAuth: { type: "http", scheme: "bearer", bearerFormat: "JWT" },
      },
      parameters: {
        IdempotencyKey: {
          name: "Idempotency-Key",
          in: "header",
          required: false,
          schema: {
            type: "string",
            pattern: "^[A-Za-z0-9._:-]{8,128}$",
          },
          description:
            "Replays the original encrypted response for 24 hours. Reuse with a different payload is rejected.",
        },
      },
      schemas: {
        Snowflake: { type: "string", pattern: "^[0-9]{17,20}$" },
        PermissionBits: { type: "string", pattern: "^[0-9]+$" },
        ApiError: {
          type: "object",
          required: ["code", "message", "traceId"],
          properties: {
            code: { type: "string" },
            message: { type: "string" },
            traceId: { type: "string", format: "uuid" },
          },
        },
      },
    },
  } as const;
}

function operation(summary: string, authenticated = true, idempotent = false) {
  return {
    summary,
    ...(authenticated ? {} : { security: [] }),
    ...(idempotent
      ? { parameters: [{ $ref: "#/components/parameters/IdempotencyKey" }] }
      : {}),
    responses: {
      "200": { description: "Success" },
      "400": { description: "Invalid request" },
      "401": { description: "Authentication required" },
      "403": { description: "Permission denied" },
    },
  };
}

export function asyncApi(origin: string) {
  const webSocketOrigin = origin.replace(/^http/, "ws");
  return {
    asyncapi: "3.0.0",
    info: { title: "CloudCord realtime API", version: "0.1.0" },
    servers: {
      production: {
        host: new URL(webSocketOrigin).host,
        protocol: new URL(webSocketOrigin).protocol.slice(0, -1),
      },
    },
    channels: {
      userGateway: {
        address: "/api/v1/gateway?ticket={ticket}",
        messages: { event: { $ref: "#/components/messages/Event" } },
      },
      channelStream: {
        address: "/api/v1/channels/{channelId}/stream?ticket={ticket}",
        messages: { event: { $ref: "#/components/messages/Event" } },
      },
      voiceControl: {
        address: "/api/v1/voice/{channelId}/control?ticket={ticket}",
        messages: { event: { $ref: "#/components/messages/Event" } },
      },
      botGateway: {
        address: "/api/v10/gateway",
        messages: {
          discordGateway: { $ref: "#/components/messages/DiscordGateway" },
        },
      },
    },
    components: {
      messages: {
        Event: {
          payload: {
            type: "object",
            required: ["op", "data"],
            properties: {
              op: { type: "integer" },
              event: { type: "string" },
              sequence: { type: "string", pattern: "^[0-9]+$" },
              data: {},
            },
            description:
              "Channel events include MESSAGE_CREATE, MESSAGE_UPDATE, MESSAGE_DELETE, reaction, pin, typing, and voice control updates.",
          },
        },
        DiscordGateway: {
          payload: {
            type: "object",
            required: ["op", "d"],
            properties: {
              op: { type: "integer" },
              t: { type: "string" },
              s: { type: "integer" },
              d: {},
            },
          },
        },
      },
    },
  } as const;
}

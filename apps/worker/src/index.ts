import {
  ALL_PERMISSIONS,
  CreateChannelSchema,
  CreateGuildSchema,
  CreateMessageSchema,
  PasswordLoginSchema,
  PermissionFlags,
  RegisterSchema,
  VoiceJoinSchema,
} from "@cloudcord/contracts";
import {
  calculatePermissions,
  createTotpSecret,
  hashPassword,
  hasPermission,
  randomToken,
  sha256,
  signAccessToken,
  snowflakeShardFor,
  totpUri,
  verifyPassword,
  verifyTotp,
} from "@cloudcord/core";
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type RegistrationResponseJSON,
} from "@simplewebauthn/server";
import { Hono, type Context } from "hono";
import { cors } from "hono/cors";
import { secureHeaders } from "hono/secure-headers";
import { requireAuth, clientIpHmac, verifyTurnstile } from "./auth";
import { decryptString, encryptString, hmac, normalizeEmail } from "./crypto";
import {
  channelDatabase,
  firstWithDualRead,
  guildDatabase,
  registerResource,
  ShardCutoverError,
  socialDatabase,
} from "./data-access";
import type { AppVariables, Env, QueueEvent } from "./env";
import { apiError, nowIso } from "./http";
import { dispatchIdentityOutbox, prepareIdentityOutbox } from "./outbox";
import { asyncApi, openApi } from "./spec";
import { databaseBinding } from "./shard-router";
import { getOptionalSecret, getSecret } from "./secrets";
import { mimeMatches, validInstanceSetting } from "./validation";

export { BotGatewayShardDO } from "./durable/bot-gateway";
export { ChannelHubDO } from "./durable/channel-hub";
export { GuildCoordinatorDO } from "./durable/guild-coordinator";
export { IdGeneratorDO } from "./durable/id-generator";
export {
  GuildSearchPartitionDO,
  MessagePartitionDO,
} from "./durable/message-partition";
export { GuildPresenceDO, UserSessionDO } from "./durable/session-hubs";
export { VoiceRoomDO } from "./durable/voice-room";
export { AccountLifecycleWorkflow } from "./workflows/account-lifecycle";
export { ShardMigrationWorkflow } from "./workflows/shard-migration";
export { BackupWorkflow } from "./workflows/backup";

type Application = { Bindings: Env; Variables: AppVariables };
const app = new Hono<Application>();

app.use(
  "*",
  secureHeaders({
    contentSecurityPolicy: {
      defaultSrc: ["'self'"],
      connectSrc: ["'self'", "wss:", "https://rtc.live.cloudflare.com"],
      imgSrc: ["'self'", "data:", "blob:"],
      mediaSrc: ["'self'", "blob:"],
      styleSrc: ["'self'", "'unsafe-inline'"],
    },
    crossOriginResourcePolicy: "same-site",
  }),
);
app.use(
  "/api/*",
  cors({
    origin: (origin, context) =>
      origin === context.env.PUBLIC_ORIGIN ? origin : context.env.PUBLIC_ORIGIN,
    allowHeaders: [
      "Authorization",
      "Content-Type",
      "Idempotency-Key",
      "X-CSRF-Token",
    ],
    allowMethods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    credentials: true,
    maxAge: 600,
  }),
);
app.use("*", async (context, next) => {
  context.set("traceId", context.req.header("cf-ray") ?? crypto.randomUUID());
  await next();
  context.header("x-trace-id", context.get("traceId"));
});
app.use("/api/v1/auth/*", async (context, next) => {
  if (["GET", "HEAD", "OPTIONS"].includes(context.req.method)) {
    await next();
    return;
  }
  const subject =
    (await clientIpHmac(context.env, context.req.raw)) ?? "local-development";
  const sensitive =
    context.req.path.endsWith("/register") ||
    context.req.path.includes("/recovery/");
  const rate = await consumeRateLimit(
    context.env,
    `public:${subject}`,
    context.req.path,
    sensitive ? 5 : 30,
    15 * 60_000,
  );
  applyRateLimitHeaders(context, rate);
  if (!rate.allowed)
    return apiError(
      context,
      429,
      "RATE_LIMITED",
      "Too many authentication attempts",
    );
  await next();
});
app.use("/api/v10/*", async (context, next) => {
  if (
    context.req.header("upgrade")?.toLowerCase() === "websocket" ||
    context.req.method === "OPTIONS"
  ) {
    await next();
    return;
  }
  const authorization = context.req.header("authorization");
  const subject = authorization
    ? await sha256(authorization)
    : ((await clientIpHmac(context.env, context.req.raw)) ??
      "local-development");
  const scope = context.req.path.includes("/messages")
    ? "discord-messages"
    : context.req.path.includes("/webhooks") ||
        context.req.path.includes("/interactions")
      ? "discord-webhooks"
      : "discord-rest";
  const limit = scope === "discord-messages" ? 120 : 300;
  const rate = await consumeRateLimit(
    context.env,
    `discord:${subject}`,
    scope,
    limit,
    60_000,
  );
  applyRateLimitHeaders(context, rate);
  context.header("x-ratelimit-bucket", scope);
  if (!rate.allowed)
    return context.json(
      {
        message: "You are being rate limited.",
        retry_after: rate.retryAfterMs / 1000,
        global: false,
      },
      429,
    );
  await next();
});

app.get("/health", (context) =>
  context.json({ status: "ok", service: "cloudcord" }),
);
app.get("/.well-known/cloudcord", (context) =>
  context.json({
    api: `${context.env.PUBLIC_ORIGIN}/api/v1`,
    discordApi: `${context.env.PUBLIC_ORIGIN}/api/v10`,
    gateway: `${context.env.PUBLIC_ORIGIN.replace(/^http/, "ws")}/api/v10/gateway`,
    version: "0.1.0",
  }),
);
app.get("/api/v1/openapi.json", (context) =>
  context.json(openApi(context.env.PUBLIC_ORIGIN)),
);
app.get("/api/v1/asyncapi.json", (context) =>
  context.json(asyncApi(context.env.PUBLIC_ORIGIN)),
);

app.post("/api/v1/auth/register", async (context) => {
  const registration = await context.env.IDENTITY_DB.prepare(
    "SELECT value FROM instance_config WHERE key='registration.enabled'",
  ).first<{ value: string }>();
  if (registration?.value === "false")
    return apiError(
      context,
      403,
      "REGISTRATION_DISABLED",
      "Public registration is disabled",
    );
  const parsed = RegisterSchema.safeParse(
    await context.req.json().catch(() => null),
  );
  if (!parsed.success)
    return apiError(
      context,
      400,
      "VALIDATION_ERROR",
      "Registration payload is invalid",
      parsed.error.flatten(),
    );
  const input = parsed.data;
  const remoteIp = context.req.header("cf-connecting-ip");
  const turnstileValid =
    context.env.ENVIRONMENT === "dev" && !context.env.TURNSTILE_SECRET
      ? input.turnstileToken === "local-dev"
      : await verifyTurnstile(context.env, input.turnstileToken, remoteIp);
  if (!turnstileValid)
    return apiError(
      context,
      403,
      "TURNSTILE_FAILED",
      "Human verification failed",
    );

  const email = normalizeEmail(input.email);
  const lookup = await hmac(
    email,
    await getSecret(context.env, "LOOKUP_HMAC_KEY"),
  );
  const existing = await context.env.IDENTITY_DB.prepare(
    "SELECT id FROM users WHERE email_lookup_hash = ?1 OR username = ?2 COLLATE NOCASE",
  )
    .bind(lookup, input.username)
    .first();
  if (existing)
    return apiError(
      context,
      409,
      "ACCOUNT_EXISTS",
      "Email or username is already registered",
    );

  const userId = await generateId(context.env, email);
  const tokenId = crypto.randomUUID();
  const emailToken = randomToken();
  const totpSecret = createTotpSecret();
  const timestamp = nowIso();
  const encryptedEmail = await encryptString(
    email,
    await getSecret(context.env, "DATA_ENCRYPTION_KEY"),
  );
  const encryptedTotp = await encryptString(
    totpSecret,
    await getSecret(context.env, "DATA_ENCRYPTION_KEY"),
  );
  const passwordHash = await hashPassword(input.password);
  const emailTokenHash = await sha256(emailToken);
  const recoveryCodes = Array.from(
    { length: 10 },
    () => `CC-${randomToken(6)}`,
  );
  const registrationStatements = [
    context.env.IDENTITY_DB.prepare(
      `INSERT INTO users(id, email_ciphertext, email_lookup_hash, username, display_name, created_at, updated_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)`,
    ).bind(
      userId,
      encryptedEmail,
      lookup,
      input.username,
      input.displayName,
      timestamp,
    ),
    context.env.IDENTITY_DB.prepare(
      "INSERT INTO password_credentials(user_id, password_hash, totp_secret_ciphertext, changed_at) VALUES (?1, ?2, ?3, ?4)",
    ).bind(userId, passwordHash, encryptedTotp, timestamp),
    context.env.IDENTITY_DB.prepare(
      "INSERT INTO one_time_tokens(id, user_id, kind, token_hash, expires_at) VALUES (?1, ?2, 'email_verify', ?3, ?4)",
    ).bind(
      tokenId,
      userId,
      emailTokenHash,
      new Date(Date.now() + 15 * 60_000).toISOString(),
    ),
  ];
  for (const code of recoveryCodes) {
    registrationStatements.push(
      context.env.IDENTITY_DB.prepare(
        "INSERT INTO recovery_codes(user_id,code_hash) VALUES (?1,?2)",
      ).bind(userId, await sha256(code)),
    );
  }
  const emailEvent: QueueEvent = {
    id: crypto.randomUUID(),
    topic: "email",
    partitionKey: userId,
    payload: {
      template: "verify-email",
      encryptedRecipient: encryptedEmail,
      token: emailToken,
    },
  };
  registrationStatements.push(
    await prepareIdentityOutbox(
      context.env,
      emailEvent,
      await getSecret(context.env, "DATA_ENCRYPTION_KEY"),
    ),
  );
  await context.env.IDENTITY_DB.batch(registrationStatements);
  await dispatchIdentityOutbox(
    context.env,
    await getSecret(context.env, "DATA_ENCRYPTION_KEY"),
    emailEvent.id,
  );
  return context.json(
    {
      userId,
      totpUri: totpUri(email, context.env.APP_NAME, totpSecret),
      recoveryCodes,
      ...(context.env.ENVIRONMENT === "prod"
        ? {}
        : { developmentEmailToken: emailToken }),
    },
    201,
  );
});

app.post("/api/v1/auth/verify-email", async (context) => {
  const body = await context.req
    .json<{ token?: string }>()
    .catch(() => ({}) as { token?: string });
  if (!body.token)
    return apiError(
      context,
      400,
      "TOKEN_REQUIRED",
      "Verification token is required",
    );
  const tokenHash = await sha256(body.token);
  const record = await context.env.IDENTITY_DB.prepare(
    "SELECT id, user_id FROM one_time_tokens WHERE token_hash = ?1 AND kind = 'email_verify' AND consumed_at IS NULL AND expires_at > ?2",
  )
    .bind(tokenHash, nowIso())
    .first<{ id: string; user_id: string }>();
  if (!record)
    return apiError(
      context,
      400,
      "TOKEN_INVALID",
      "Verification token is invalid or expired",
    );
  const timestamp = nowIso();
  await context.env.IDENTITY_DB.batch([
    context.env.IDENTITY_DB.prepare(
      "UPDATE one_time_tokens SET consumed_at = ?1 WHERE id = ?2",
    ).bind(timestamp, record.id),
    context.env.IDENTITY_DB.prepare(
      "UPDATE users SET status = 'active', updated_at = ?1 WHERE id = ?2",
    ).bind(timestamp, record.user_id),
  ]);
  return context.json({ verified: true });
});

app.post("/api/v1/auth/login", async (context) => {
  const parsed = PasswordLoginSchema.safeParse(
    await context.req.json().catch(() => null),
  );
  if (!parsed.success)
    return apiError(
      context,
      400,
      "VALIDATION_ERROR",
      "Login payload is invalid",
      parsed.error.flatten(),
    );
  const lookup = await hmac(
    normalizeEmail(parsed.data.email),
    await getSecret(context.env, "LOOKUP_HMAC_KEY"),
  );
  const user = await context.env.IDENTITY_DB.prepare(
    `SELECT u.id, u.username, u.display_name, u.status, p.password_hash, p.totp_secret_ciphertext, p.totp_last_counter
       FROM users u JOIN password_credentials p ON p.user_id = u.id WHERE u.email_lookup_hash = ?1`,
  )
    .bind(lookup)
    .first<{
      id: string;
      username: string;
      display_name: string;
      status: string;
      password_hash: string;
      totp_secret_ciphertext: string;
      totp_last_counter: number | null;
    }>();
  if (
    !user ||
    !(await verifyPassword(user.password_hash, parsed.data.password))
  ) {
    return apiError(
      context,
      401,
      "INVALID_CREDENTIALS",
      "Email, password, or TOTP is invalid",
    );
  }
  if (user.status !== "active")
    return apiError(
      context,
      403,
      "ACCOUNT_INACTIVE",
      "Verify the email address before signing in",
    );
  const { decryptString } = await import("./crypto");
  const totpSecret = await decryptString(
    user.totp_secret_ciphertext,
    await getSecret(context.env, "DATA_ENCRYPTION_KEY"),
  );
  if (
    !verifyTotp(
      parsed.data.totp,
      parsed.data.email,
      context.env.APP_NAME,
      totpSecret,
    )
  ) {
    return apiError(
      context,
      401,
      "INVALID_CREDENTIALS",
      "Email, password, or TOTP is invalid",
    );
  }
  const totpCounter = Math.floor(Date.now() / 30_000);
  if (user.totp_last_counter !== null && totpCounter <= user.totp_last_counter)
    return apiError(
      context,
      401,
      "TOTP_REPLAY",
      "This TOTP code was already used",
    );
  await context.env.IDENTITY_DB.prepare(
    "UPDATE password_credentials SET totp_last_counter=?1 WHERE user_id=?2",
  )
    .bind(totpCounter, user.id)
    .run();
  return context.json(await createSession(context.env, context.req.raw, user));
});

app.post("/api/v1/auth/passkey/options", async (context) => {
  const options = await generateAuthenticationOptions({
    rpID: context.env.RP_ID,
    userVerification: "required",
  });
  await context.env.IDENTITY_DB.prepare(
    "INSERT INTO auth_challenges(id, kind, challenge_hash, expires_at) VALUES (?1, 'passkey_login', ?2, ?3)",
  )
    .bind(
      crypto.randomUUID(),
      await sha256(options.challenge),
      new Date(Date.now() + 5 * 60_000).toISOString(),
    )
    .run();
  return context.json(options);
});

app.post("/api/v1/auth/passkey/verify", async (context) => {
  const response = await context.req
    .json<AuthenticationResponseJSON>()
    .catch(() => null);
  if (!response)
    return apiError(
      context,
      400,
      "VALIDATION_ERROR",
      "Passkey response is required",
    );
  const passkey = await context.env.IDENTITY_DB.prepare(
    `SELECT p.id, p.user_id, p.public_key, p.counter, p.transports, u.username, u.display_name, u.status
       FROM passkeys p JOIN users u ON u.id=p.user_id WHERE p.credential_id=?1`,
  )
    .bind(response.id)
    .first<{
      id: string;
      user_id: string;
      public_key: ArrayBuffer;
      counter: number;
      transports: string;
      username: string;
      display_name: string;
      status: string;
    }>();
  if (!passkey || passkey.status !== "active")
    return apiError(
      context,
      401,
      "PASSKEY_REJECTED",
      "Passkey is unknown or account is inactive",
    );
  const verification = await verifyAuthenticationResponse({
    response,
    expectedChallenge: async (challenge) =>
      consumeChallenge(context.env, "passkey_login", challenge),
    expectedOrigin: context.env.PUBLIC_ORIGIN,
    expectedRPID: context.env.RP_ID,
    requireUserVerification: true,
    credential: {
      id: response.id,
      publicKey: new Uint8Array(passkey.public_key),
      counter: passkey.counter,
      transports: JSON.parse(passkey.transports),
    },
  });
  if (!verification.verified)
    return apiError(
      context,
      401,
      "PASSKEY_REJECTED",
      "Passkey verification failed",
    );
  await context.env.IDENTITY_DB.prepare(
    "UPDATE passkeys SET counter=?1, last_used_at=?2 WHERE id=?3",
  )
    .bind(verification.authenticationInfo.newCounter, nowIso(), passkey.id)
    .run();
  return context.json(
    await createSession(context.env, context.req.raw, {
      id: passkey.user_id,
      username: passkey.username,
      display_name: passkey.display_name,
    }),
  );
});

app.post("/api/v1/auth/refresh", async (context) => {
  const body = await context.req
    .json<{ refreshToken?: string }>()
    .catch(() => ({}) as { refreshToken?: string });
  if (!body.refreshToken)
    return apiError(
      context,
      400,
      "REFRESH_REQUIRED",
      "Refresh token is required",
    );
  const tokenHash = await sha256(body.refreshToken);
  const session = await context.env.IDENTITY_DB.prepare(
    `SELECT s.id, s.user_id, s.family_id, s.expires_at, u.username, u.display_name
       FROM sessions s JOIN users u ON u.id=s.user_id
      WHERE s.refresh_hash=?1 AND s.revoked_at IS NULL AND s.expires_at>?2`,
  )
    .bind(tokenHash, nowIso())
    .first<{
      id: string;
      user_id: string;
      family_id: string;
      expires_at: string;
      username: string;
      display_name: string;
    }>();
  if (!session) {
    const reused = await context.env.IDENTITY_DB.prepare(
      "SELECT family_id FROM sessions WHERE previous_refresh_hash=?1 AND revoked_at IS NULL",
    )
      .bind(tokenHash)
      .first<{ family_id: string }>();
    if (reused)
      await context.env.IDENTITY_DB.prepare(
        "UPDATE sessions SET revoked_at=?1 WHERE family_id=?2",
      )
        .bind(nowIso(), reused.family_id)
        .run();
    return apiError(
      context,
      401,
      "REFRESH_REJECTED",
      reused
        ? "Refresh token reuse detected; session family revoked"
        : "Refresh token is invalid",
    );
  }
  const nextRefresh = randomToken(48);
  const nextHash = await sha256(nextRefresh);
  await context.env.IDENTITY_DB.prepare(
    "UPDATE sessions SET previous_refresh_hash=refresh_hash, refresh_hash=?1, last_seen_at=?2 WHERE id=?3",
  )
    .bind(nextHash, nowIso(), session.id)
    .run();
  const nextAccessToken = await makeAccessToken(
    context.env,
    session.user_id,
    session.id,
    session.username,
    session.display_name,
  );
  return context.json({
    accessToken: nextAccessToken,
    refreshToken: nextRefresh,
    expiresIn: Number(context.env.ACCESS_TOKEN_TTL_SECONDS),
  });
});

app.post("/api/v1/auth/desktop/token", async (context) => {
  const body = await context.req
    .json<{ code?: string; verifier?: string; redirectUri?: string }>()
    .catch(
      () => ({}) as { code?: string; verifier?: string; redirectUri?: string },
    );
  if (
    !body.code ||
    !body.verifier ||
    body.verifier.length < 43 ||
    body.verifier.length > 128 ||
    !/^[A-Za-z0-9._~-]+$/.test(body.verifier) ||
    body.redirectUri !== "cloudcord://auth/callback"
  )
    return apiError(
      context,
      400,
      "DESKTOP_CODE_INVALID",
      "A valid desktop authorization code and PKCE verifier are required",
    );
  const record = await context.env.IDENTITY_DB.prepare(
    `SELECT d.id,d.user_id,d.pkce_challenge,u.username,u.display_name
       FROM desktop_auth_codes d JOIN users u ON u.id=d.user_id
      WHERE d.code_hash=?1 AND d.redirect_uri=?2 AND d.consumed_at IS NULL
        AND d.expires_at>?3 AND u.status='active'`,
  )
    .bind(await sha256(body.code), body.redirectUri, nowIso())
    .first<{
      id: string;
      user_id: string;
      pkce_challenge: string;
      username: string;
      display_name: string;
    }>();
  if (!record || (await pkceChallenge(body.verifier)) !== record.pkce_challenge)
    return apiError(
      context,
      400,
      "DESKTOP_CODE_INVALID",
      "Desktop authorization code is invalid or expired",
    );
  const claimed = await context.env.IDENTITY_DB.prepare(
    "UPDATE desktop_auth_codes SET consumed_at=?1 WHERE id=?2 AND consumed_at IS NULL",
  )
    .bind(nowIso(), record.id)
    .run();
  if (claimed.meta.changes !== 1)
    return apiError(
      context,
      400,
      "DESKTOP_CODE_USED",
      "Desktop authorization code has already been used",
    );
  return context.json(
    await createSession(context.env, context.req.raw, {
      id: record.user_id,
      username: record.username,
      display_name: record.display_name,
    }),
  );
});

app.post("/api/v1/auth/recovery/request", async (context) => {
  const body = await context.req
    .json<{ email?: string; turnstileToken?: string }>()
    .catch(() => ({}) as { email?: string; turnstileToken?: string });
  if (!body.email || !body.turnstileToken)
    return apiError(
      context,
      400,
      "VALIDATION_ERROR",
      "email and Turnstile token are required",
    );
  const turnstileValid =
    context.env.ENVIRONMENT === "dev" && !context.env.TURNSTILE_SECRET
      ? body.turnstileToken === "local-dev"
      : await verifyTurnstile(
          context.env,
          body.turnstileToken,
          context.req.header("cf-connecting-ip"),
        );
  if (!turnstileValid)
    return apiError(
      context,
      403,
      "TURNSTILE_FAILED",
      "Human verification failed",
    );
  const lookup = await hmac(
    normalizeEmail(body.email),
    await getSecret(context.env, "LOOKUP_HMAC_KEY"),
  );
  const user = await context.env.IDENTITY_DB.prepare(
    "SELECT id,email_ciphertext FROM users WHERE email_lookup_hash=?1 AND status='active'",
  )
    .bind(lookup)
    .first<{ id: string; email_ciphertext: string }>();
  let developmentRecoveryToken: string | undefined;
  if (user) {
    const token = randomToken(32);
    developmentRecoveryToken = token;
    const emailEvent: QueueEvent = {
      id: crypto.randomUUID(),
      topic: "email",
      partitionKey: user.id,
      payload: {
        template: "account-recovery",
        encryptedRecipient: user.email_ciphertext,
        token,
      },
    };
    await context.env.IDENTITY_DB.batch([
      context.env.IDENTITY_DB.prepare(
        "INSERT INTO one_time_tokens(id,user_id,kind,token_hash,expires_at) VALUES (?1,?2,'account_recovery',?3,?4)",
      ).bind(
        crypto.randomUUID(),
        user.id,
        await sha256(token),
        new Date(Date.now() + 15 * 60_000).toISOString(),
      ),
      await prepareIdentityOutbox(
        context.env,
        emailEvent,
        await getSecret(context.env, "DATA_ENCRYPTION_KEY"),
      ),
    ]);
    await dispatchIdentityOutbox(
      context.env,
      await getSecret(context.env, "DATA_ENCRYPTION_KEY"),
      emailEvent.id,
    );
  }
  return context.json(
    {
      accepted: true,
      ...(context.env.ENVIRONMENT === "prod"
        ? {}
        : { developmentRecoveryToken }),
    },
    202,
  );
});

app.post("/api/v1/auth/recovery/complete", async (context) => {
  const body = await context.req
    .json<{ token?: string; newPassword?: string }>()
    .catch(() => ({}) as { token?: string; newPassword?: string });
  if (!body.token || !body.newPassword || body.newPassword.length < 12)
    return apiError(
      context,
      400,
      "VALIDATION_ERROR",
      "A valid token and 12-character password are required",
    );
  const record = await context.env.IDENTITY_DB.prepare(
    "SELECT id,user_id FROM one_time_tokens WHERE kind='account_recovery' AND token_hash=?1 AND consumed_at IS NULL AND expires_at>?2",
  )
    .bind(await sha256(body.token), nowIso())
    .first<{ id: string; user_id: string }>();
  if (!record)
    return apiError(
      context,
      400,
      "TOKEN_INVALID",
      "Recovery token is invalid or expired",
    );
  const timestamp = nowIso();
  await context.env.IDENTITY_DB.batch([
    context.env.IDENTITY_DB.prepare(
      "UPDATE one_time_tokens SET consumed_at=?1 WHERE id=?2 AND consumed_at IS NULL",
    ).bind(timestamp, record.id),
    context.env.IDENTITY_DB.prepare(
      "UPDATE password_credentials SET password_hash=?1,changed_at=?2 WHERE user_id=?3",
    ).bind(await hashPassword(body.newPassword), timestamp, record.user_id),
    context.env.IDENTITY_DB.prepare(
      "UPDATE sessions SET revoked_at=?1 WHERE user_id=?2 AND revoked_at IS NULL",
    ).bind(timestamp, record.user_id),
  ]);
  return context.json({ recovered: true, allSessionsRevoked: true });
});

app.get("/api/v1/directory", async (context) => {
  const limit = Math.min(
    Math.max(Number(context.req.query("limit") ?? 50), 1),
    100,
  );
  const result = await context.env.IDENTITY_DB.prepare(
    `SELECT guild_id AS guildId,name,description,member_count AS memberCount,updated_at AS updatedAt
       FROM guild_directory WHERE enabled=1
       ORDER BY member_count DESC,updated_at DESC LIMIT ?1`,
  )
    .bind(limit)
    .all();
  return context.json({ guilds: result.results });
});

app.get("/api/v1/invites/:code/preview", async (context) => {
  const entry = await context.env.IDENTITY_DB.prepare(
    "SELECT guild_id,channel_id FROM invite_directory WHERE code=?1",
  )
    .bind(context.req.param("code"))
    .first<{ guild_id: string; channel_id: string }>();
  if (!entry)
    return apiError(context, 404, "INVITE_NOT_FOUND", "Invite was not found");
  const guild = await guildDatabase(context.env, entry.guild_id);
  const preview = await guild.db
    .prepare(
      `SELECT i.code,i.channel_id AS channelId,i.max_uses AS maxUses,i.uses,i.expires_at AS expiresAt,
              g.id AS guildId,g.name,g.description
         FROM invites i JOIN guilds g ON g.id=i.guild_id
        WHERE i.code=?1 AND (i.expires_at IS NULL OR i.expires_at>?2)
          AND (i.max_uses IS NULL OR i.uses<i.max_uses)`,
    )
    .bind(context.req.param("code"), nowIso())
    .first();
  if (!preview)
    return apiError(context, 404, "INVITE_EXPIRED", "Invite is unavailable");
  return context.json(preview);
});

app.use("/api/v1/*", requireAuth);
app.use("/api/v1/*", async (context, next) => {
  if (["GET", "HEAD", "OPTIONS"].includes(context.req.method)) {
    await next();
    return;
  }
  const origin = context.req.header("origin");
  const allowedOrigins = new Set([
    context.env.PUBLIC_ORIGIN,
    "tauri://localhost",
    "http://tauri.localhost",
    "https://tauri.localhost",
  ]);
  if (origin && !allowedOrigins.has(origin))
    return apiError(
      context,
      403,
      "ORIGIN_DENIED",
      "The request origin is not allowed",
    );
  const path = context.req.path;
  const [scope, limit] = path.includes("/messages")
    ? ["messages", 120]
    : path.includes("/uploads")
      ? ["uploads", 30]
      : path.includes("friend-requests")
        ? ["social", 30]
        : ["writes", 240];
  const rate = await consumeRateLimit(
    context.env,
    `session:${context.get("auth").sessionId}`,
    scope,
    limit,
    60_000,
  );
  applyRateLimitHeaders(context, rate);
  if (!rate.allowed)
    return apiError(context, 429, "RATE_LIMITED", "Write rate limit exceeded");
  await next();
});
app.use("/api/v1/*", async (context, next) => {
  if (["GET", "HEAD", "OPTIONS"].includes(context.req.method)) {
    await next();
    return;
  }
  const key = context.req.header("idempotency-key");
  if (!key) {
    await next();
    return;
  }
  if (!/^[A-Za-z0-9._:-]{8,128}$/.test(key))
    return apiError(
      context,
      400,
      "INVALID_IDEMPOTENCY_KEY",
      "Idempotency-Key must be 8 to 128 safe ASCII characters",
    );
  const auth = context.get("auth");
  const operation = `${context.req.method}:${context.req.path}`;
  const length = Number(context.req.header("content-length") ?? 0);
  const bodyFingerprint =
    length <= 1024 * 1024
      ? await context.req.raw.clone().text()
      : `${length}:${context.req.header("content-type") ?? ""}`;
  const requestHash = await sha256(bodyFingerprint);
  const encryptionKey = await getSecret(context.env, "DATA_ENCRYPTION_KEY");
  const reservation = await encryptString(
    JSON.stringify({ state: "pending" }),
    encryptionKey,
  );
  const inserted = await context.env.IDENTITY_DB.prepare(
    `INSERT OR IGNORE INTO idempotency_keys(actor_id,operation,key,response_json,expires_at,request_hash)
     VALUES (?1,?2,?3,?4,?5,?6)`,
  )
    .bind(
      auth.id,
      operation,
      key,
      reservation,
      new Date(Date.now() + 24 * 60 * 60_000).toISOString(),
      requestHash,
    )
    .run();
  if (inserted.meta.changes === 0) {
    const stored = await context.env.IDENTITY_DB.prepare(
      `SELECT response_json,response_status,response_headers,request_hash
         FROM idempotency_keys WHERE actor_id=?1 AND operation=?2 AND key=?3`,
    )
      .bind(auth.id, operation, key)
      .first<{
        response_json: string;
        response_status: number | null;
        response_headers: string | null;
        request_hash: string | null;
      }>();
    if (!stored || stored.request_hash !== requestHash)
      return apiError(
        context,
        409,
        "IDEMPOTENCY_KEY_REUSED",
        "The idempotency key was already used with a different request",
      );
    const replay = JSON.parse(
      await decryptString(stored.response_json, encryptionKey),
    ) as { state: "pending" | "complete"; body?: string };
    if (replay.state === "pending") {
      context.header("retry-after", "1");
      return apiError(
        context,
        409,
        "IDEMPOTENCY_IN_PROGRESS",
        "The original request is still in progress",
      );
    }
    const headers = new Headers(
      JSON.parse(stored.response_headers ?? "[]") as [string, string][],
    );
    headers.set("idempotency-replayed", "true");
    return new Response(replay.body ?? null, {
      status: stored.response_status ?? 200,
      headers,
    });
  }
  try {
    await next();
    if (context.res.status >= 500)
      throw new Error("Response was not committed");
    const response = context.res.clone();
    const body = await response.text();
    const encryptedResponse = await encryptString(
      JSON.stringify({ state: "complete", body }),
      encryptionKey,
    );
    await context.env.IDENTITY_DB.prepare(
      `UPDATE idempotency_keys
          SET response_json=?1,response_status=?2,response_headers=?3
        WHERE actor_id=?4 AND operation=?5 AND key=?6`,
    )
      .bind(
        encryptedResponse,
        response.status,
        JSON.stringify([...response.headers.entries()]),
        auth.id,
        operation,
        key,
      )
      .run();
  } catch (error) {
    await context.env.IDENTITY_DB.prepare(
      "DELETE FROM idempotency_keys WHERE actor_id=?1 AND operation=?2 AND key=?3 AND response_status IS NULL",
    )
      .bind(auth.id, operation, key)
      .run();
    throw error;
  }
});

app.post("/api/v1/auth/desktop/authorize", async (context) => {
  const body = await context.req
    .json<{ challenge?: string; redirectUri?: string }>()
    .catch(() => ({}) as { challenge?: string; redirectUri?: string });
  if (
    !body.challenge ||
    !/^[A-Za-z0-9_-]{43}$/.test(body.challenge) ||
    body.redirectUri !== "cloudcord://auth/callback"
  )
    return apiError(
      context,
      400,
      "DESKTOP_PKCE_INVALID",
      "A valid S256 PKCE challenge and desktop redirect URI are required",
    );
  const code = randomToken(48);
  const id = crypto.randomUUID();
  const expiresAt = new Date(Date.now() + 5 * 60_000).toISOString();
  await context.env.IDENTITY_DB.prepare(
    `INSERT INTO desktop_auth_codes(
       id,user_id,code_hash,pkce_challenge,redirect_uri,expires_at,created_at
     ) VALUES (?1,?2,?3,?4,?5,?6,?7)`,
  )
    .bind(
      id,
      context.get("auth").id,
      await sha256(code),
      body.challenge,
      body.redirectUri,
      expiresAt,
      nowIso(),
    )
    .run();
  const deepLink = new URL(body.redirectUri);
  deepLink.searchParams.set("code", code);
  return context.json({ deepLink: deepLink.toString(), expiresAt });
});

app.get("/api/v1/me", async (context) => {
  const auth = context.get("auth");
  const row = await context.env.IDENTITY_DB.prepare(
    "SELECT id, username, display_name, avatar_key, status, locale, created_at FROM users WHERE id=?1",
  )
    .bind(auth.id)
    .first();
  return context.json({
    ...row,
    administrator: await isAdmin(context.env, auth.id),
  });
});

app.post("/api/v1/me/export", async (context) => {
  const auth = context.get("auth");
  const active = await context.env.IDENTITY_DB.prepare(
    `SELECT id FROM account_lifecycle_jobs
      WHERE user_id=?1 AND kind='export' AND phase IN ('queued','running')
      ORDER BY created_at DESC LIMIT 1`,
  )
    .bind(auth.id)
    .first<{ id: string }>();
  if (active)
    return apiError(
      context,
      409,
      "ACCOUNT_EXPORT_ACTIVE",
      "An account export is already running",
      { jobId: active.id },
    );
  const jobId = await generateId(context.env, `${auth.id}:export`);
  const timestamp = nowIso();
  await context.env.IDENTITY_DB.prepare(
    `INSERT INTO account_lifecycle_jobs(id,user_id,kind,phase,created_at,updated_at)
     VALUES (?1,?2,'export','queued',?3,?3)`,
  )
    .bind(jobId, auth.id, timestamp)
    .run();
  try {
    await context.env.ACCOUNT_LIFECYCLE.create({
      id: jobId,
      params: { jobId, userId: auth.id, kind: "export" },
    });
  } catch (cause) {
    await failLifecycleStart(context.env, jobId, cause);
    throw cause;
  }
  return context.json({ id: jobId, kind: "export", phase: "queued" }, 202);
});

app.post("/api/v1/me/delete/passkey-options", async (context) => {
  const auth = context.get("auth");
  const credentials = await context.env.IDENTITY_DB.prepare(
    "SELECT credential_id,transports FROM passkeys WHERE user_id=?1",
  )
    .bind(auth.id)
    .all<{ credential_id: string; transports: string }>();
  if (credentials.results.length === 0)
    return apiError(
      context,
      409,
      "PASSKEY_UNAVAILABLE",
      "This account has no passkey",
    );
  const options = await generateAuthenticationOptions({
    rpID: context.env.RP_ID,
    userVerification: "required",
    allowCredentials: credentials.results.map((credential) => ({
      id: credential.credential_id,
      transports: JSON.parse(credential.transports),
    })),
  });
  await context.env.IDENTITY_DB.prepare(
    `INSERT INTO auth_challenges(id,user_id,kind,challenge_hash,expires_at)
     VALUES (?1,?2,'account_delete_passkey',?3,?4)`,
  )
    .bind(
      crypto.randomUUID(),
      auth.id,
      await sha256(options.challenge),
      new Date(Date.now() + 5 * 60_000).toISOString(),
    )
    .run();
  return context.json(options);
});

app.post("/api/v1/me/delete", async (context) => {
  const auth = context.get("auth");
  const body = await context.req
    .json<{
      confirmation?: string;
      password?: string;
      totp?: string;
      passkey?: AuthenticationResponseJSON;
    }>()
    .catch(() => null);
  if (!body || body.confirmation !== auth.username)
    return apiError(
      context,
      400,
      "ACCOUNT_DELETE_CONFIRMATION_REQUIRED",
      "Type the exact username to confirm account deletion",
    );
  const credential = await context.env.IDENTITY_DB.prepare(
    `SELECT password_hash,totp_secret_ciphertext,totp_last_counter
       FROM password_credentials WHERE user_id=?1`,
  )
    .bind(auth.id)
    .first<{
      password_hash: string;
      totp_secret_ciphertext: string;
      totp_last_counter: number | null;
    }>();
  let authorized = false;
  if (credential && body.password && body.totp) {
    const totpSecret = await decryptString(
      credential.totp_secret_ciphertext,
      await getSecret(context.env, "DATA_ENCRYPTION_KEY"),
    );
    const counter = Math.floor(Date.now() / 30_000);
    authorized =
      (await verifyPassword(credential.password_hash, body.password)) &&
      verifyTotp(body.totp, auth.username, context.env.APP_NAME, totpSecret) &&
      (credential.totp_last_counter === null ||
        counter > credential.totp_last_counter);
    if (authorized)
      await context.env.IDENTITY_DB.prepare(
        "UPDATE password_credentials SET totp_last_counter=?1 WHERE user_id=?2",
      )
        .bind(counter, auth.id)
        .run();
  } else if (body.passkey) {
    authorized = await verifyAccountDeletionPasskey(
      context.env,
      auth.id,
      body.passkey,
    );
  }
  if (!authorized)
    return apiError(
      context,
      401,
      "ACCOUNT_DELETE_REAUTH_FAILED",
      "Password and TOTP or a user-verified passkey is required",
    );
  const ownedGuild = await findOwnedGuild(context.env, auth.id);
  if (ownedGuild)
    return apiError(
      context,
      409,
      "OWNED_GUILD_REMAINS",
      "Transfer ownership or delete every owned guild first",
      { guildId: ownedGuild },
    );
  const existing = await context.env.IDENTITY_DB.prepare(
    `SELECT id FROM account_lifecycle_jobs
      WHERE user_id=?1 AND kind='delete' AND phase IN ('queued','running')
      LIMIT 1`,
  )
    .bind(auth.id)
    .first<{ id: string }>();
  if (existing)
    return apiError(
      context,
      409,
      "ACCOUNT_DELETE_ACTIVE",
      "Account deletion is already running",
      { jobId: existing.id },
    );
  const jobId = await generateId(context.env, `${auth.id}:delete`);
  const timestamp = nowIso();
  await context.env.IDENTITY_DB.prepare(
    `INSERT INTO account_lifecycle_jobs(id,user_id,kind,phase,created_at,updated_at)
     VALUES (?1,?2,'delete','queued',?3,?3)`,
  )
    .bind(jobId, auth.id, timestamp)
    .run();
  try {
    await context.env.ACCOUNT_LIFECYCLE.create({
      id: jobId,
      params: { jobId, userId: auth.id, kind: "delete" },
    });
  } catch (cause) {
    await failLifecycleStart(context.env, jobId, cause);
    throw cause;
  }
  return context.json({ id: jobId, kind: "delete", phase: "queued" }, 202);
});

app.get("/api/v1/me/lifecycle/:jobId", async (context) => {
  const job = await context.env.IDENTITY_DB.prepare(
    `SELECT id,kind,phase,object_key AS objectKey,error,created_at AS createdAt,
            updated_at AS updatedAt
       FROM account_lifecycle_jobs WHERE id=?1 AND user_id=?2`,
  )
    .bind(context.req.param("jobId"), context.get("auth").id)
    .first();
  if (!job)
    return apiError(
      context,
      404,
      "ACCOUNT_LIFECYCLE_NOT_FOUND",
      "Account lifecycle job was not found",
    );
  return context.json(job);
});

app.get("/api/v1/me/lifecycle/:jobId/file", async (context) => {
  const auth = context.get("auth");
  const job = await context.env.IDENTITY_DB.prepare(
    `SELECT phase,object_key FROM account_lifecycle_jobs
      WHERE id=?1 AND user_id=?2 AND kind='export'`,
  )
    .bind(context.req.param("jobId"), auth.id)
    .first<{ phase: string; object_key: string | null }>();
  if (!job || job.phase !== "complete" || !job.object_key)
    return apiError(
      context,
      404,
      "ACCOUNT_EXPORT_NOT_READY",
      "Account export is not ready",
    );
  const requestedKey = context.req.query("key") ?? job.object_key;
  const prefix = `exports/${auth.id}/${context.req.param("jobId")}/`;
  if (!requestedKey.startsWith(prefix) || requestedKey.includes(".."))
    return apiError(
      context,
      403,
      "ACCOUNT_EXPORT_FILE_DENIED",
      "Export file is outside this job",
    );
  const object = await context.env.MEDIA.get(requestedKey);
  if (!object)
    return apiError(
      context,
      404,
      "ACCOUNT_EXPORT_FILE_NOT_FOUND",
      "Export file was not found",
    );
  return new Response(object.body, {
    headers: {
      "content-type": object.httpMetadata?.contentType ?? "application/json",
      "content-disposition": `attachment; filename="${requestedKey.split("/").at(-1) ?? "export.json"}"`,
      "cache-control": "private, no-store",
    },
  });
});

app.post("/api/v1/ws-ticket", async (context) => {
  const ticket = randomToken(32);
  await context.env.IDENTITY_DB.prepare(
    "INSERT INTO auth_challenges(id,user_id,kind,challenge_hash,expires_at) VALUES (?1,?2,'websocket_ticket',?3,?4)",
  )
    .bind(
      crypto.randomUUID(),
      context.get("auth").id,
      await sha256(ticket),
      new Date(Date.now() + 60_000).toISOString(),
    )
    .run();
  return context.json({ ticket, expiresIn: 60 });
});

app.post("/api/v1/passkeys/options", async (context) => {
  const auth = context.get("auth");
  const options = await generateRegistrationOptions({
    rpName: context.env.APP_NAME,
    rpID: context.env.RP_ID,
    userID: new TextEncoder().encode(auth.id),
    userName: auth.username,
    attestationType: "none",
    authenticatorSelection: {
      residentKey: "preferred",
      userVerification: "required",
    },
  });
  await context.env.IDENTITY_DB.prepare(
    "INSERT INTO auth_challenges(id, user_id, kind, challenge_hash, expires_at) VALUES (?1, ?2, 'passkey_register', ?3, ?4)",
  )
    .bind(
      crypto.randomUUID(),
      auth.id,
      await sha256(options.challenge),
      new Date(Date.now() + 5 * 60_000).toISOString(),
    )
    .run();
  return context.json(options);
});

app.post("/api/v1/passkeys/verify", async (context) => {
  const response = await context.req
    .json<RegistrationResponseJSON>()
    .catch(() => null);
  if (!response)
    return apiError(
      context,
      400,
      "VALIDATION_ERROR",
      "Passkey response is required",
    );
  const auth = context.get("auth");
  const verification = await verifyRegistrationResponse({
    response,
    expectedChallenge: async (challenge) =>
      consumeChallenge(context.env, "passkey_register", challenge, auth.id),
    expectedOrigin: context.env.PUBLIC_ORIGIN,
    expectedRPID: context.env.RP_ID,
    requireUserVerification: true,
  });
  if (!verification.verified || !verification.registrationInfo)
    return apiError(
      context,
      400,
      "PASSKEY_REJECTED",
      "Passkey registration failed",
    );
  const credential = verification.registrationInfo.credential;
  await context.env.IDENTITY_DB.prepare(
    "INSERT INTO passkeys(id, user_id, credential_id, public_key, counter, transports, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
  )
    .bind(
      crypto.randomUUID(),
      auth.id,
      credential.id,
      credential.publicKey,
      credential.counter,
      JSON.stringify(credential.transports ?? []),
      nowIso(),
    )
    .run();
  return context.json({ registered: true }, 201);
});

app.post("/api/v1/auth/logout", async (context) => {
  await context.env.IDENTITY_DB.prepare(
    "UPDATE sessions SET revoked_at=?1 WHERE id=?2",
  )
    .bind(nowIso(), context.get("auth").sessionId)
    .run();
  return new Response(null, { status: 204 });
});

app.get("/api/v1/users/search", async (context) => {
  const query = context.req.query("q")?.trim();
  if (!query || query.length < 2) return context.json({ users: [] });
  const rows = await context.env.IDENTITY_DB.prepare(
    "SELECT id, username, display_name AS displayName, avatar_key AS avatarKey FROM users WHERE status='active' AND (username LIKE ?1 OR display_name LIKE ?1) LIMIT 20",
  )
    .bind(`${query.replaceAll("%", "\\%").replaceAll("_", "\\_")}%`)
    .all();
  return context.json({ users: rows.results });
});

app.get("/api/v1/relationships", async (context) => {
  const social = await socialDatabase(context.env, context.get("auth").id);
  const rows = await social.db
    .prepare(
      "SELECT target_user_id AS userId, kind, created_at AS createdAt FROM relationships WHERE user_id=?1 ORDER BY updated_at DESC",
    )
    .bind(context.get("auth").id)
    .all<{ userId: string; kind: string; createdAt: string }>();
  const users = await Promise.all(
    rows.results.map(async (relationship) => {
      const user = await context.env.IDENTITY_DB.prepare(
        "SELECT username, display_name AS displayName, avatar_key AS avatarKey FROM users WHERE id=?1",
      )
        .bind(relationship.userId)
        .first();
      return { ...relationship, user };
    }),
  );
  return context.json({ relationships: users });
});

app.post("/api/v1/friend-requests", async (context) => {
  const body = await context.req
    .json<{ username?: string }>()
    .catch(() => ({}) as { username?: string });
  if (!body.username)
    return apiError(context, 400, "VALIDATION_ERROR", "username is required");
  const auth = context.get("auth");
  const target = await context.env.IDENTITY_DB.prepare(
    "SELECT id FROM users WHERE username=?1 COLLATE NOCASE AND status='active'",
  )
    .bind(body.username)
    .first<{ id: string }>();
  if (!target || target.id === auth.id)
    return apiError(context, 404, "USER_NOT_FOUND", "User was not found");
  const [ownSocial, targetSocial] = await Promise.all([
    socialDatabase(context.env, auth.id),
    socialDatabase(context.env, target.id),
  ]);
  const [blockedBySelf, blockedByTarget] = await Promise.all([
    ownSocial.db
      .prepare(
        "SELECT 1 FROM relationships WHERE user_id=?1 AND target_user_id=?2 AND kind='blocked'",
      )
      .bind(auth.id, target.id)
      .first(),
    targetSocial.db
      .prepare(
        "SELECT 1 FROM relationships WHERE user_id=?1 AND target_user_id=?2 AND kind='blocked'",
      )
      .bind(target.id, auth.id)
      .first(),
  ]);
  const blocked = blockedBySelf || blockedByTarget;
  if (blocked)
    return apiError(
      context,
      403,
      "RELATIONSHIP_BLOCKED",
      "A block prevents this request",
    );
  const timestamp = nowIso();
  await ownSocial.db
    .prepare(
      "INSERT INTO relationships(user_id,target_user_id,kind,created_at,updated_at) VALUES (?1,?2,'friend_pending_outgoing',?3,?3) ON CONFLICT(user_id,target_user_id) DO UPDATE SET kind=excluded.kind,updated_at=excluded.updated_at",
    )
    .bind(auth.id, target.id, timestamp)
    .run();
  await targetSocial.db
    .prepare(
      "INSERT INTO relationships(user_id,target_user_id,kind,created_at,updated_at) VALUES (?1,?2,'friend_pending_incoming',?3,?3) ON CONFLICT(user_id,target_user_id) DO UPDATE SET kind=excluded.kind,updated_at=excluded.updated_at",
    )
    .bind(target.id, auth.id, timestamp)
    .run();
  return context.json({ requested: true }, 201);
});

app.post("/api/v1/friend-requests/:userId/accept", async (context) => {
  const auth = context.get("auth");
  const other = context.req.param("userId");
  const timestamp = nowIso();
  const [ownSocial, otherSocial] = await Promise.all([
    socialDatabase(context.env, auth.id),
    socialDatabase(context.env, other),
  ]);
  const pending = await ownSocial.db
    .prepare(
      "SELECT 1 FROM relationships WHERE user_id=?1 AND target_user_id=?2 AND kind='friend_pending_incoming'",
    )
    .bind(auth.id, other)
    .first();
  if (!pending)
    return apiError(
      context,
      404,
      "REQUEST_NOT_FOUND",
      "Friend request was not found",
    );
  await ownSocial.db
    .prepare(
      "UPDATE relationships SET kind='friend',updated_at=?1 WHERE user_id=?2 AND target_user_id=?3",
    )
    .bind(timestamp, auth.id, other)
    .run();
  await otherSocial.db
    .prepare(
      "UPDATE relationships SET kind='friend',updated_at=?1 WHERE user_id=?2 AND target_user_id=?3",
    )
    .bind(timestamp, other, auth.id)
    .run();
  return context.json({ friends: true });
});

app.put("/api/v1/blocks/:userId", async (context) => {
  const auth = context.get("auth");
  const other = context.req.param("userId");
  const timestamp = nowIso();
  const [ownSocial, otherSocial] = await Promise.all([
    socialDatabase(context.env, auth.id),
    socialDatabase(context.env, other),
  ]);
  await otherSocial.db
    .prepare("DELETE FROM relationships WHERE user_id=?1 AND target_user_id=?2")
    .bind(other, auth.id)
    .run();
  await ownSocial.db
    .prepare(
      "INSERT INTO relationships(user_id,target_user_id,kind,created_at,updated_at) VALUES (?1,?2,'blocked',?3,?3) ON CONFLICT(user_id,target_user_id) DO UPDATE SET kind='blocked',updated_at=excluded.updated_at",
    )
    .bind(auth.id, other, timestamp)
    .run();
  return new Response(null, { status: 204 });
});

app.get("/api/v1/conversations", async (context) => {
  const social = await socialDatabase(context.env, context.get("auth").id);
  const rows = await social.db
    .prepare(
      `SELECT conversation_id AS id, kind, name, owner_id AS ownerId,
            channel_id AS channelId, joined_at AS createdAt
       FROM conversation_membership_index WHERE user_id=?1 ORDER BY joined_at DESC`,
    )
    .bind(context.get("auth").id)
    .all();
  const conversations = await Promise.all(
    (
      rows.results as Array<{
        id: string;
        kind: string;
        name: string | null;
        ownerId: string;
        channelId: string;
        createdAt: string;
      }>
    ).map(async (conversation) => {
      const routed = await socialDatabase(context.env, conversation.id);
      const members = await routed.db
        .prepare(
          "SELECT user_id FROM conversation_members WHERE conversation_id=?1 ORDER BY joined_at",
        )
        .bind(conversation.id)
        .all<{ user_id: string }>();
      const users = await Promise.all(
        members.results.map((member) =>
          discordUser(context.env, member.user_id),
        ),
      );
      const peers = users.filter((user) => user.id !== context.get("auth").id);
      return {
        ...conversation,
        displayName:
          conversation.name ??
          (peers.map((user) => user.global_name ?? user.username).join(", ") ||
            "Direct Message"),
        members: users,
      };
    }),
  );
  return context.json({ conversations });
});

app.post("/api/v1/conversations", async (context) => {
  const body = await context.req
    .json<{ userIds?: string[]; name?: string }>()
    .catch(() => ({}) as { userIds?: string[]; name?: string });
  const auth = context.get("auth");
  const userIds = [...new Set([auth.id, ...(body.userIds ?? [])])];
  if (userIds.length < 2 || userIds.length > 10)
    return apiError(
      context,
      400,
      "VALIDATION_ERROR",
      "A conversation requires 2 to 10 unique members",
    );
  const id = await generateId(context.env, auth.id);
  const channelId = await generateId(context.env, id);
  const timestamp = nowIso();
  const conversationSocial = await socialDatabase(context.env, id);
  const statements = [
    conversationSocial.db
      .prepare(
        "INSERT INTO conversations(id,kind,name,owner_id,channel_id,created_at) VALUES (?1,?2,?3,?4,?5,?6)",
      )
      .bind(
        id,
        userIds.length === 2 ? "dm" : "group_dm",
        body.name ?? null,
        auth.id,
        channelId,
        timestamp,
      ),
  ];
  for (const userId of userIds)
    statements.push(
      conversationSocial.db
        .prepare(
          "INSERT INTO conversation_members(conversation_id,user_id,joined_at) VALUES (?1,?2,?3)",
        )
        .bind(id, userId, timestamp),
    );
  await conversationSocial.db.batch(statements);
  await context.env.IDENTITY_DB.batch([
    context.env.IDENTITY_DB.prepare(
      "INSERT INTO resource_directory(resource_id,resource_type,owner_id,created_at) VALUES (?1,'conversation',?1,?2)",
    ).bind(id, timestamp),
    context.env.IDENTITY_DB.prepare(
      "INSERT INTO resource_directory(resource_id,resource_type,owner_id,created_at) VALUES (?1,'dm_channel',?2,?3)",
    ).bind(channelId, id, timestamp),
  ]);
  await Promise.all(
    userIds.map(async (userId) => {
      const memberSocial = await socialDatabase(context.env, userId);
      await memberSocial.db
        .prepare(
          `INSERT INTO conversation_membership_index(user_id,conversation_id,channel_id,kind,name,owner_id,joined_at)
           VALUES (?1,?2,?3,?4,?5,?6,?7)
           ON CONFLICT(user_id,conversation_id) DO UPDATE SET
             channel_id=excluded.channel_id,kind=excluded.kind,name=excluded.name,owner_id=excluded.owner_id`,
        )
        .bind(
          userId,
          id,
          channelId,
          userIds.length === 2 ? "dm" : "group_dm",
          body.name ?? null,
          auth.id,
          timestamp,
        )
        .run();
    }),
  );
  return context.json(
    {
      id,
      channelId,
      kind: userIds.length === 2 ? "dm" : "group_dm",
      memberIds: userIds,
    },
    201,
  );
});

app.post("/api/v1/invites/:code", async (context) => {
  const auth = context.get("auth");
  const entry = await context.env.IDENTITY_DB.prepare(
    "SELECT guild_id,channel_id FROM invite_directory WHERE code=?1",
  )
    .bind(context.req.param("code"))
    .first<{ guild_id: string; channel_id: string }>();
  if (!entry)
    return apiError(context, 404, "INVITE_NOT_FOUND", "Invite was not found");
  const guild = await guildDatabase(context.env, entry.guild_id);
  if (
    await guild.db
      .prepare(
        "SELECT 1 FROM bans WHERE guild_id=?1 AND user_id=?2 AND (expires_at IS NULL OR expires_at>?3)",
      )
      .bind(entry.guild_id, auth.id, nowIso())
      .first()
  )
    return apiError(
      context,
      403,
      "GUILD_BANNED",
      "You are banned from this guild",
    );
  const existing = await guild.db
    .prepare("SELECT 1 FROM members WHERE guild_id=?1 AND user_id=?2")
    .bind(entry.guild_id, auth.id)
    .first();
  if (!existing) {
    const timestamp = nowIso();
    const claimed = await guild.db
      .prepare(
        `UPDATE invites SET uses=uses+1
          WHERE code=?1 AND (expires_at IS NULL OR expires_at>?2)
            AND (max_uses IS NULL OR uses<max_uses)`,
      )
      .bind(context.req.param("code"), timestamp)
      .run();
    if (claimed.meta.changes !== 1)
      return apiError(context, 404, "INVITE_EXPIRED", "Invite is unavailable");
    await guild.db
      .prepare(
        "INSERT INTO members(guild_id,user_id,role_ids,joined_at) VALUES (?1,?2,?3,?4)",
      )
      .bind(
        entry.guild_id,
        auth.id,
        JSON.stringify([entry.guild_id]),
        timestamp,
      )
      .run();
    const social = await socialDatabase(context.env, auth.id);
    await social.db
      .prepare(
        `INSERT OR IGNORE INTO guild_membership_index(user_id,guild_id,joined_at)
         VALUES (?1,?2,?3)`,
      )
      .bind(auth.id, entry.guild_id, timestamp)
      .run();
    const count = await guild.db
      .prepare("SELECT count(*) AS count FROM members WHERE guild_id=?1")
      .bind(entry.guild_id)
      .first<{ count: number }>();
    await context.env.IDENTITY_DB.prepare(
      "UPDATE guild_directory SET member_count=?1,updated_at=?2 WHERE guild_id=?3",
    )
      .bind(count?.count ?? 1, timestamp, entry.guild_id)
      .run();
    await appendGuildAudit(
      context.env,
      entry.guild_id,
      auth.id,
      "MEMBER_JOIN",
      auth.id,
    );
  }
  const summary = await guild.db
    .prepare(
      "SELECT id,owner_id AS ownerId,name,description,icon_key AS iconKey FROM guilds WHERE id=?1",
    )
    .bind(entry.guild_id)
    .first();
  return context.json({ ...summary, defaultChannelId: entry.channel_id });
});

app.get("/api/v1/guilds", async (context) => {
  const auth = context.get("auth");
  const social = await socialDatabase(context.env, auth.id);
  const memberships = await social.db
    .prepare(
      "SELECT guild_id AS guildId FROM guild_membership_index WHERE user_id=?1 ORDER BY joined_at",
    )
    .bind(auth.id)
    .all<{ guildId: string }>();
  const guilds = (
    await Promise.all(
      memberships.results.map(async ({ guildId }) => {
        const routed = await guildDatabase(context.env, guildId);
        return firstWithDualRead<{
          id: string;
          ownerId: string;
          name: string;
          description: string | null;
          iconKey: string | null;
        }>(routed, (db) =>
          db
            .prepare(
              "SELECT id,owner_id AS ownerId,name,description,icon_key AS iconKey FROM guilds WHERE id=?1",
            )
            .bind(guildId),
        );
      }),
    )
  ).filter((guild) => guild !== null);
  return context.json({ guilds });
});

app.post("/api/v1/guilds", async (context) => {
  const parsed = CreateGuildSchema.safeParse(
    await context.req.json().catch(() => null),
  );
  if (!parsed.success)
    return apiError(
      context,
      400,
      "VALIDATION_ERROR",
      "Guild payload is invalid",
      parsed.error.flatten(),
    );
  const auth = context.get("auth");
  const guildId = await generateId(context.env, auth.id);
  const everyoneRoleId = guildId;
  const channelId = await generateId(context.env, guildId);
  const timestamp = nowIso();
  const defaultPermissions = (
    PermissionFlags.VIEW_CHANNEL |
    PermissionFlags.SEND_MESSAGES |
    PermissionFlags.ADD_REACTIONS |
    PermissionFlags.ATTACH_FILES |
    PermissionFlags.READ_MESSAGE_HISTORY |
    PermissionFlags.SEND_POLLS |
    PermissionFlags.CONNECT |
    PermissionFlags.SPEAK |
    PermissionFlags.USE_VAD
  ).toString();
  const guild = await guildDatabase(context.env, guildId);
  await guild.db.batch([
    guild.db
      .prepare(
        "INSERT INTO guilds(id, owner_id, name, description, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
      )
      .bind(
        guildId,
        auth.id,
        parsed.data.name,
        parsed.data.description ?? null,
        timestamp,
      ),
    guild.db
      .prepare(
        "INSERT INTO roles(id, guild_id, name, permissions, position, created_at) VALUES (?1, ?1, '@everyone', ?2, 0, ?3)",
      )
      .bind(guildId, defaultPermissions, timestamp),
    guild.db
      .prepare(
        "INSERT INTO members(guild_id, user_id, role_ids, joined_at) VALUES (?1, ?2, ?3, ?4)",
      )
      .bind(guildId, auth.id, JSON.stringify([everyoneRoleId]), timestamp),
    guild.db
      .prepare(
        "INSERT INTO channels(id, guild_id, type, name, position, created_at) VALUES (?1, ?2, 'GUILD_TEXT', 'general', 0, ?3)",
      )
      .bind(channelId, guildId, timestamp),
  ]);
  const ownerSocial = await socialDatabase(context.env, auth.id);
  await ownerSocial.db
    .prepare(
      "INSERT INTO guild_membership_index(user_id,guild_id,joined_at) VALUES (?1,?2,?3)",
    )
    .bind(auth.id, guildId, timestamp)
    .run();
  await registerResource(
    context.env,
    channelId,
    "guild_channel",
    guildId,
    timestamp,
  );
  await context.env.IDENTITY_DB.prepare(
    `INSERT INTO guild_directory(guild_id,name,description,enabled,member_count,updated_at)
     VALUES (?1,?2,?3,0,1,?4)`,
  )
    .bind(guildId, parsed.data.name, parsed.data.description ?? null, timestamp)
    .run();
  return context.json(
    {
      id: guildId,
      ownerId: auth.id,
      name: parsed.data.name,
      description: parsed.data.description ?? null,
      defaultChannelId: channelId,
    },
    201,
  );
});

app.get("/api/v1/guilds/:guildId/channels", async (context) => {
  const guildId = context.req.param("guildId");
  if (!(await isMember(context.env, guildId, context.get("auth").id)))
    return apiError(
      context,
      403,
      "MISSING_ACCESS",
      "Guild membership required",
    );
  const guild = await guildDatabase(context.env, guildId);
  const rows = await guild.db
    .prepare(
      "SELECT id, guild_id AS guildId, parent_id AS parentId, type, name, topic, position, last_message_id AS lastMessageId FROM channels WHERE guild_id=?1 ORDER BY position",
    )
    .bind(guildId)
    .all();
  return context.json({ channels: rows.results });
});

app.post("/api/v1/guilds/:guildId/channels", async (context) => {
  const guildId = context.req.param("guildId");
  const auth = context.get("auth");
  if (
    !(await hasGuildPermission(
      context.env,
      guildId,
      null,
      auth.id,
      PermissionFlags.MANAGE_CHANNELS,
    ))
  )
    return apiError(
      context,
      403,
      "MISSING_PERMISSIONS",
      "Manage Channels permission is required",
    );
  const parsed = CreateChannelSchema.safeParse(
    await context.req.json().catch(() => null),
  );
  if (!parsed.success)
    return apiError(
      context,
      400,
      "VALIDATION_ERROR",
      "Channel payload is invalid",
      parsed.error.flatten(),
    );
  const id = await generateId(context.env, guildId);
  const guild = await guildDatabase(context.env, guildId);
  if (parsed.data.parentId) {
    const parent = await guild.db
      .prepare("SELECT type FROM channels WHERE id=?1 AND guild_id=?2")
      .bind(parsed.data.parentId, guildId)
      .first<{ type: string }>();
    if (!parent)
      return apiError(
        context,
        400,
        "PARENT_NOT_FOUND",
        "Parent channel was not found",
      );
  }
  const position = await guild.db
    .prepare(
      "SELECT coalesce(max(position), -1)+1 AS value FROM channels WHERE guild_id=?1",
    )
    .bind(guildId)
    .first<{ value: number }>();
  const createdAt = nowIso();
  const statements = [
    guild.db
      .prepare(
        "INSERT INTO channels(id, guild_id, parent_id, type, name, topic, position, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
      )
      .bind(
        id,
        guildId,
        parsed.data.parentId ?? null,
        parsed.data.type,
        parsed.data.name,
        parsed.data.topic ?? null,
        position?.value ?? 0,
        createdAt,
      ),
  ];
  if (parsed.data.type.includes("THREAD"))
    statements.push(
      guild.db
        .prepare(
          `INSERT INTO thread_metadata(channel_id,owner_id,created_at)
           VALUES (?1,?2,?3)`,
        )
        .bind(id, auth.id, createdAt),
    );
  await guild.db.batch(statements);
  await registerResource(context.env, id, "guild_channel", guildId, createdAt);
  return context.json(
    {
      id,
      guildId,
      parentId: parsed.data.parentId ?? null,
      type: parsed.data.type,
      name: parsed.data.name,
      topic: parsed.data.topic ?? null,
      position: position?.value ?? 0,
      lastMessageId: null,
    },
    201,
  );
});

app.post("/api/v1/channels/:channelId/threads", async (context) => {
  const auth = context.get("auth");
  const parent = await accessibleChannel(
    context.env,
    context.req.param("channelId"),
    auth.id,
  );
  if (
    !parent ||
    parent.guild_id.startsWith("dm:") ||
    ![
      "GUILD_TEXT",
      "GUILD_ANNOUNCEMENT",
      "GUILD_FORUM",
      "GUILD_MEDIA",
    ].includes(parent.type)
  )
    return apiError(
      context,
      404,
      "THREAD_PARENT_INVALID",
      "A thread-capable guild channel is required",
    );
  const body = await context.req
    .json<{
      name?: string;
      private?: boolean;
      content?: string;
      autoArchiveMinutes?: number;
    }>()
    .catch(() => null);
  if (
    !body?.name ||
    body.name.length > 100 ||
    (body.content !== undefined && body.content.length > 4000) ||
    ![60, 1440, 4320, 10080].includes(body.autoArchiveMinutes ?? 1440)
  )
    return apiError(
      context,
      400,
      "THREAD_INVALID",
      "Thread name, content, or archive duration is invalid",
    );
  const required = body.private
    ? PermissionFlags.CREATE_PRIVATE_THREADS
    : PermissionFlags.CREATE_PUBLIC_THREADS;
  if (!hasPermission(parent.permissions, required))
    return apiError(
      context,
      403,
      "MISSING_PERMISSIONS",
      "Thread creation permission is required",
    );
  const type =
    parent.type === "GUILD_ANNOUNCEMENT"
      ? "ANNOUNCEMENT_THREAD"
      : body.private
        ? "PRIVATE_THREAD"
        : "PUBLIC_THREAD";
  const guild = await guildDatabase(context.env, parent.guild_id);
  const id = await generateId(context.env, parent.id);
  const createdAt = nowIso();
  const position = await guild.db
    .prepare(
      "SELECT coalesce(max(position),-1)+1 AS value FROM channels WHERE guild_id=?1",
    )
    .bind(parent.guild_id)
    .first<{ value: number }>();
  await guild.db.batch([
    guild.db
      .prepare(
        `INSERT INTO channels(id,guild_id,parent_id,type,name,position,created_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7)`,
      )
      .bind(
        id,
        parent.guild_id,
        parent.id,
        type,
        body.name,
        position?.value ?? 0,
        createdAt,
      ),
    guild.db
      .prepare(
        `INSERT INTO thread_metadata(channel_id,owner_id,auto_archive_minutes,created_at)
         VALUES (?1,?2,?3,?4)`,
      )
      .bind(id, auth.id, body.autoArchiveMinutes ?? 1440, createdAt),
    guild.db
      .prepare(
        "INSERT INTO thread_members(channel_id,user_id,joined_at) VALUES (?1,?2,?3)",
      )
      .bind(id, auth.id, createdAt),
    guild.db
      .prepare(
        `INSERT INTO permission_overwrites(channel_id,target_id,target_type,allow_bits,deny_bits)
         SELECT ?1,target_id,target_type,allow_bits,deny_bits
           FROM permission_overwrites WHERE channel_id=?2`,
      )
      .bind(id, parent.id),
  ]);
  await registerResource(
    context.env,
    id,
    "guild_channel",
    parent.guild_id,
    createdAt,
  );
  let message: Record<string, unknown> | null = null;
  if (body.content) {
    const messageId = await generateId(context.env, id);
    const response = await channelStub(context.env, id).fetch(
      new Request("https://do/messages", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          id: messageId,
          channelId: id,
          authorId: auth.id,
          authorUsername: auth.username,
          authorDisplayName: auth.displayName,
          authorBot: false,
          content: body.content,
          createdAt,
          replyToId: null,
          attachments: [],
          partitionKey: parent.guild_id,
          slowmodeSeconds: 0,
          bypassSlowmode: true,
        }),
      }),
    );
    if (!response.ok)
      return apiError(
        context,
        500,
        "THREAD_MESSAGE_FAILED",
        "Thread was created without its first message",
      );
    message = await response.json<Record<string, unknown>>();
  }
  return context.json(
    {
      thread: {
        id,
        guildId: parent.guild_id,
        parentId: parent.id,
        type,
        name: body.name,
        topic: null,
        position: position?.value ?? 0,
        lastMessageId: message?.id ?? null,
      },
      message,
    },
    201,
  );
});

app.patch("/api/v1/guilds/:guildId/channels/:channelId", async (context) => {
  const guildId = context.req.param("guildId");
  const auth = context.get("auth");
  if (
    !(await hasGuildPermission(
      context.env,
      guildId,
      context.req.param("channelId"),
      auth.id,
      PermissionFlags.MANAGE_CHANNELS,
    ))
  )
    return apiError(
      context,
      403,
      "MISSING_PERMISSIONS",
      "Manage Channels permission is required",
    );
  const body = await context.req
    .json<{ name?: string; topic?: string | null; slowmodeSeconds?: number }>()
    .catch(
      () =>
        ({}) as {
          name?: string;
          topic?: string | null;
          slowmodeSeconds?: number;
        },
    );
  if (
    (body.name !== undefined &&
      (body.name.length < 1 || body.name.length > 100)) ||
    (body.topic !== undefined &&
      body.topic !== null &&
      body.topic.length > 4096) ||
    (body.slowmodeSeconds !== undefined &&
      (!Number.isInteger(body.slowmodeSeconds) ||
        body.slowmodeSeconds < 0 ||
        body.slowmodeSeconds > 21_600))
  )
    return apiError(
      context,
      400,
      "VALIDATION_ERROR",
      "Channel settings are invalid",
    );
  const guild = await guildDatabase(context.env, guildId);
  const current = await guild.db
    .prepare(
      "SELECT name,topic,slowmode_seconds FROM channels WHERE id=?1 AND guild_id=?2",
    )
    .bind(context.req.param("channelId"), guildId)
    .first<{ name: string; topic: string | null; slowmode_seconds: number }>();
  if (!current)
    return apiError(context, 404, "CHANNEL_NOT_FOUND", "Channel was not found");
  const next = {
    name: body.name ?? current.name,
    topic: body.topic === undefined ? current.topic : body.topic,
    slowmodeSeconds: body.slowmodeSeconds ?? current.slowmode_seconds,
  };
  await guild.db
    .prepare(
      "UPDATE channels SET name=?1,topic=?2,slowmode_seconds=?3 WHERE id=?4 AND guild_id=?5",
    )
    .bind(
      next.name,
      next.topic,
      next.slowmodeSeconds,
      context.req.param("channelId"),
      guildId,
    )
    .run();
  await appendGuildAudit(
    context.env,
    guildId,
    auth.id,
    "CHANNEL_UPDATE",
    context.req.param("channelId"),
    null,
    [next],
  );
  return context.json({ id: context.req.param("channelId"), guildId, ...next });
});

app.post("/api/v1/guilds/:guildId/invites", async (context) => {
  const guildId = context.req.param("guildId");
  const auth = context.get("auth");
  if (
    !(await hasGuildPermission(
      context.env,
      guildId,
      null,
      auth.id,
      PermissionFlags.CREATE_INSTANT_INVITE,
    ))
  )
    return apiError(
      context,
      403,
      "MISSING_PERMISSIONS",
      "Create Invite permission is required",
    );
  const body = await context.req
    .json<{ channelId?: string; maxUses?: number; expiresInSeconds?: number }>()
    .catch(
      () =>
        ({}) as {
          channelId?: string;
          maxUses?: number;
          expiresInSeconds?: number;
        },
    );
  if (
    !body.channelId ||
    (body.maxUses !== undefined &&
      (!Number.isInteger(body.maxUses) ||
        body.maxUses < 1 ||
        body.maxUses > 10_000)) ||
    (body.expiresInSeconds !== undefined &&
      (!Number.isInteger(body.expiresInSeconds) ||
        body.expiresInSeconds < 60 ||
        body.expiresInSeconds > 30 * 24 * 60 * 60))
  )
    return apiError(
      context,
      400,
      "VALIDATION_ERROR",
      "Invite settings are invalid",
    );
  const guild = await guildDatabase(context.env, guildId);
  const channel = await guild.db
    .prepare("SELECT id FROM channels WHERE id=?1 AND guild_id=?2")
    .bind(body.channelId, guildId)
    .first();
  if (!channel)
    return apiError(context, 404, "CHANNEL_NOT_FOUND", "Channel was not found");
  const code = randomToken(9);
  const timestamp = nowIso();
  const expiresAt = body.expiresInSeconds
    ? new Date(Date.now() + body.expiresInSeconds * 1000).toISOString()
    : null;
  await guild.db
    .prepare(
      `INSERT INTO invites(code,guild_id,channel_id,creator_id,max_uses,expires_at,created_at)
       VALUES (?1,?2,?3,?4,?5,?6,?7)`,
    )
    .bind(
      code,
      guildId,
      body.channelId,
      auth.id,
      body.maxUses ?? null,
      expiresAt,
      timestamp,
    )
    .run();
  await context.env.IDENTITY_DB.prepare(
    "INSERT INTO invite_directory(code,guild_id,channel_id,created_at) VALUES (?1,?2,?3,?4)",
  )
    .bind(code, guildId, body.channelId, timestamp)
    .run();
  await appendGuildAudit(context.env, guildId, auth.id, "INVITE_CREATE", code);
  return context.json(
    {
      code,
      guildId,
      channelId: body.channelId,
      maxUses: body.maxUses ?? null,
      expiresAt,
    },
    201,
  );
});

app.get("/api/v1/guilds/:guildId/roles", async (context) => {
  const guildId = context.req.param("guildId");
  if (!(await isMember(context.env, guildId, context.get("auth").id)))
    return apiError(
      context,
      403,
      "MISSING_ACCESS",
      "Guild membership required",
    );
  const guild = await guildDatabase(context.env, guildId);
  const result = await guild.db
    .prepare(
      "SELECT id,guild_id AS guildId,name,permissions,position,color,managed FROM roles WHERE guild_id=?1 ORDER BY position",
    )
    .bind(guildId)
    .all();
  return context.json({ roles: result.results });
});

app.post("/api/v1/guilds/:guildId/roles", async (context) => {
  const guildId = context.req.param("guildId");
  const auth = context.get("auth");
  if (
    !(await hasGuildPermission(
      context.env,
      guildId,
      null,
      auth.id,
      PermissionFlags.MANAGE_ROLES,
    ))
  )
    return apiError(
      context,
      403,
      "MISSING_PERMISSIONS",
      "Manage Roles permission is required",
    );
  const body = await context.req
    .json<{ name?: string; permissions?: string; color?: number }>()
    .catch(
      () => ({}) as { name?: string; permissions?: string; color?: number },
    );
  if (!body.name || body.name.length > 100)
    return apiError(context, 400, "VALIDATION_ERROR", "Role name is required");
  const permissions = parsePermissionBits(body.permissions ?? "0");
  if (permissions === null)
    return apiError(
      context,
      400,
      "VALIDATION_ERROR",
      "permissions must be a supported decimal bitfield",
    );
  const id = await generateId(context.env, guildId);
  const guild = await guildDatabase(context.env, guildId);
  const position = await guild.db
    .prepare(
      "SELECT coalesce(max(position),0)+1 AS value FROM roles WHERE guild_id=?1",
    )
    .bind(guildId)
    .first<{ value: number }>();
  await guild.db
    .prepare(
      "INSERT INTO roles(id,guild_id,name,permissions,position,color,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7)",
    )
    .bind(
      id,
      guildId,
      body.name,
      permissions.toString(),
      position?.value ?? 1,
      body.color ?? 0,
      nowIso(),
    )
    .run();
  return context.json(
    {
      id,
      guildId,
      name: body.name,
      permissions: permissions.toString(),
      position: position?.value ?? 1,
      color: body.color ?? 0,
    },
    201,
  );
});

app.put("/api/v1/guilds/:guildId/members/:userId/roles", async (context) => {
  const guildId = context.req.param("guildId");
  const auth = context.get("auth");
  if (
    !(await hasGuildPermission(
      context.env,
      guildId,
      null,
      auth.id,
      PermissionFlags.MANAGE_ROLES,
    ))
  )
    return apiError(
      context,
      403,
      "MISSING_PERMISSIONS",
      "Manage Roles permission is required",
    );
  const body = await context.req
    .json<{ roleIds?: string[] }>()
    .catch(() => ({}) as { roleIds?: string[] });
  const guild = await guildDatabase(context.env, guildId);
  const roles = await guild.db
    .prepare("SELECT id,position,managed FROM roles WHERE guild_id=?1")
    .bind(guildId)
    .all<{ id: string; position: number; managed: number }>();
  const target = await guild.db
    .prepare("SELECT role_ids FROM members WHERE guild_id=?1 AND user_id=?2")
    .bind(guildId, context.req.param("userId"))
    .first<{ role_ids: string }>();
  if (!target)
    return apiError(
      context,
      404,
      "MEMBER_NOT_FOUND",
      "Guild member was not found",
    );
  const currentRoleIds = new Set(JSON.parse(target.role_ids) as string[]);
  const managedRoleIds = new Set(
    roles.results.filter((role) => role.managed).map((role) => role.id),
  );
  if (
    (body.roleIds ?? []).some(
      (id) => managedRoleIds.has(id) && !currentRoleIds.has(id),
    )
  )
    return apiError(
      context,
      400,
      "MANAGED_ROLE",
      "Managed roles cannot be assigned manually",
    );
  const roleIds = [
    ...new Set([
      guildId,
      ...(body.roleIds ?? []),
      ...[...currentRoleIds].filter((id) => managedRoleIds.has(id)),
    ]),
  ];
  if (roleIds.some((id) => !roles.results.some((role) => role.id === id)))
    return apiError(
      context,
      400,
      "ROLE_NOT_FOUND",
      "One or more roles do not belong to this guild",
    );
  const owner = await isGuildOwner(context.env, guildId, auth.id);
  if (!owner) {
    const actor = await guild.db
      .prepare("SELECT role_ids FROM members WHERE guild_id=?1 AND user_id=?2")
      .bind(guildId, auth.id)
      .first<{ role_ids: string }>();
    const actorIds = JSON.parse(actor?.role_ids ?? "[]") as string[];
    const actorTop = Math.max(
      0,
      ...roles.results
        .filter((role) => actorIds.includes(role.id))
        .map((role) => role.position),
    );
    const assignedTop = Math.max(
      0,
      ...roles.results
        .filter((role) => roleIds.includes(role.id))
        .map((role) => role.position),
    );
    if (assignedTop >= actorTop)
      return apiError(
        context,
        403,
        "ROLE_HIERARCHY",
        "Cannot assign a role at or above your highest role",
      );
  }
  const result = await guild.db
    .prepare("UPDATE members SET role_ids=?1 WHERE guild_id=?2 AND user_id=?3")
    .bind(JSON.stringify(roleIds), guildId, context.req.param("userId"))
    .run();
  if (result.meta.changes !== 1)
    return apiError(
      context,
      409,
      "ROLE_UPDATE_FAILED",
      "Roles were not updated",
    );
  return context.json({
    guildId,
    userId: context.req.param("userId"),
    roleIds,
  });
});

app.put(
  "/api/v1/channels/:channelId/permissions/:targetId",
  async (context) => {
    const auth = context.get("auth");
    const channel = await accessibleChannel(
      context.env,
      context.req.param("channelId"),
      auth.id,
    );
    if (!channel || channel.guild_id.startsWith("dm:"))
      return apiError(
        context,
        404,
        "CHANNEL_NOT_FOUND",
        "Guild channel was not found",
      );
    if (!hasPermission(channel.permissions, PermissionFlags.MANAGE_CHANNELS))
      return apiError(
        context,
        403,
        "MISSING_PERMISSIONS",
        "Manage Channels permission is required",
      );
    const body = await context.req
      .json<{ type?: "role" | "member"; allow?: string; deny?: string }>()
      .catch(
        () =>
          ({}) as { type?: "role" | "member"; allow?: string; deny?: string },
      );
    const allow = parsePermissionBits(body.allow ?? "0");
    const deny = parsePermissionBits(body.deny ?? "0");
    if (!body.type || allow === null || deny === null)
      return apiError(
        context,
        400,
        "VALIDATION_ERROR",
        "type, allow, and deny are required permission fields",
      );
    const guild = await guildDatabase(context.env, channel.guild_id);
    await guild.db
      .prepare(
        `INSERT INTO permission_overwrites(channel_id,target_id,target_type,allow_bits,deny_bits)
     VALUES (?1,?2,?3,?4,?5)
     ON CONFLICT(channel_id,target_id) DO UPDATE SET target_type=excluded.target_type,allow_bits=excluded.allow_bits,deny_bits=excluded.deny_bits`,
      )
      .bind(
        channel.id,
        context.req.param("targetId"),
        body.type,
        allow.toString(),
        deny.toString(),
      )
      .run();
    return context.json({
      channelId: channel.id,
      targetId: context.req.param("targetId"),
      type: body.type,
      allow: allow.toString(),
      deny: deny.toString(),
    });
  },
);

app.get("/api/v1/guilds/:guildId/events", async (context) => {
  const guildId = context.req.param("guildId");
  if (!(await isMember(context.env, guildId, context.get("auth").id)))
    return apiError(
      context,
      403,
      "MISSING_ACCESS",
      "Guild membership required",
    );
  const guild = await guildDatabase(context.env, guildId);
  const result = await guild.db
    .prepare(
      "SELECT id,guild_id AS guildId,channel_id AS channelId,creator_id AS creatorId,name,description,starts_at AS startsAt,ends_at AS endsAt,status FROM scheduled_events WHERE guild_id=?1 ORDER BY starts_at",
    )
    .bind(guildId)
    .all();
  return context.json({ events: result.results });
});

app.post("/api/v1/guilds/:guildId/events", async (context) => {
  const guildId = context.req.param("guildId");
  const auth = context.get("auth");
  if (
    !(await hasGuildPermission(
      context.env,
      guildId,
      null,
      auth.id,
      PermissionFlags.MANAGE_EVENTS,
    ))
  )
    return apiError(
      context,
      403,
      "MISSING_PERMISSIONS",
      "Manage Events permission is required",
    );
  const body = await context.req
    .json<{
      name?: string;
      description?: string;
      channelId?: string;
      startsAt?: string;
      endsAt?: string;
    }>()
    .catch(
      () =>
        ({}) as {
          name?: string;
          description?: string;
          channelId?: string;
          startsAt?: string;
          endsAt?: string;
        },
    );
  if (!body.name || !body.startsAt || Number.isNaN(Date.parse(body.startsAt)))
    return apiError(
      context,
      400,
      "VALIDATION_ERROR",
      "name and a valid startsAt are required",
    );
  const id = await generateId(context.env, guildId);
  const guild = await guildDatabase(context.env, guildId);
  await guild.db
    .prepare(
      "INSERT INTO scheduled_events(id,guild_id,channel_id,creator_id,name,description,starts_at,ends_at,status,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,'scheduled',?9)",
    )
    .bind(
      id,
      guildId,
      body.channelId ?? null,
      auth.id,
      body.name,
      body.description ?? null,
      new Date(body.startsAt).toISOString(),
      body.endsAt ? new Date(body.endsAt).toISOString() : null,
      nowIso(),
    )
    .run();
  return context.json({ id, guildId, ...body, status: "scheduled" }, 201);
});

app.patch("/api/v1/guilds/:guildId/directory", async (context) => {
  const guildId = context.req.param("guildId");
  const auth = context.get("auth");
  if (
    !(await hasGuildPermission(
      context.env,
      guildId,
      null,
      auth.id,
      PermissionFlags.MANAGE_GUILD,
    ))
  )
    return apiError(
      context,
      403,
      "MISSING_PERMISSIONS",
      "Manage Guild permission is required",
    );
  const body = await context.req
    .json<{ enabled?: boolean }>()
    .catch(() => ({}) as { enabled?: boolean });
  if (typeof body.enabled !== "boolean")
    return apiError(context, 400, "VALIDATION_ERROR", "enabled is required");
  const guild = await guildDatabase(context.env, guildId);
  const summary = await guild.db
    .prepare("SELECT name,description FROM guilds WHERE id=?1")
    .bind(guildId)
    .first<{ name: string; description: string | null }>();
  if (!summary)
    return apiError(context, 404, "GUILD_NOT_FOUND", "Guild was not found");
  const count = await guild.db
    .prepare("SELECT count(*) AS count FROM members WHERE guild_id=?1")
    .bind(guildId)
    .first<{ count: number }>();
  await context.env.IDENTITY_DB.prepare(
    `INSERT INTO guild_directory(guild_id,name,description,enabled,member_count,updated_at)
     VALUES (?1,?2,?3,?4,?5,?6)
     ON CONFLICT(guild_id) DO UPDATE SET name=excluded.name,description=excluded.description,
       enabled=excluded.enabled,member_count=excluded.member_count,updated_at=excluded.updated_at`,
  )
    .bind(
      guildId,
      summary.name,
      summary.description,
      Number(body.enabled),
      count?.count ?? 0,
      nowIso(),
    )
    .run();
  await appendGuildAudit(
    context.env,
    guildId,
    auth.id,
    "DIRECTORY_UPDATE",
    guildId,
    null,
    [{ key: "enabled", value: body.enabled }],
  );
  return context.json({ guildId, enabled: body.enabled });
});

app.get("/api/v1/guilds/:guildId/members", async (context) => {
  const guildId = context.req.param("guildId");
  if (!(await isMember(context.env, guildId, context.get("auth").id)))
    return apiError(
      context,
      403,
      "MISSING_ACCESS",
      "Guild membership required",
    );
  const guild = await guildDatabase(context.env, guildId);
  const members = await guild.db
    .prepare(
      `SELECT user_id AS userId,nickname,role_ids AS roleIds,timeout_until AS timeoutUntil,joined_at AS joinedAt
         FROM members WHERE guild_id=?1 ORDER BY joined_at LIMIT 100`,
    )
    .bind(guildId)
    .all<{
      userId: string;
      nickname: string | null;
      roleIds: string;
      timeoutUntil: string | null;
      joinedAt: string;
    }>();
  const result = await Promise.all(
    members.results.map(async (member) => {
      const user = await context.env.IDENTITY_DB.prepare(
        "SELECT username,display_name AS displayName,avatar_key AS avatarKey FROM users WHERE id=?1",
      )
        .bind(member.userId)
        .first();
      return { ...member, roleIds: JSON.parse(member.roleIds), user };
    }),
  );
  return context.json({ members: result });
});

app.delete("/api/v1/guilds/:guildId/members/:userId", async (context) => {
  const guildId = context.req.param("guildId");
  const targetId = context.req.param("userId");
  const auth = context.get("auth");
  if (
    !(await hasGuildPermission(
      context.env,
      guildId,
      null,
      auth.id,
      PermissionFlags.KICK_MEMBERS,
    )) ||
    !(await canModerateMember(context.env, guildId, auth.id, targetId))
  )
    return apiError(
      context,
      403,
      "MISSING_PERMISSIONS",
      "Kick Members permission and a higher role are required",
    );
  const guild = await guildDatabase(context.env, guildId);
  const removed = await guild.db
    .prepare("DELETE FROM members WHERE guild_id=?1 AND user_id=?2")
    .bind(guildId, targetId)
    .run();
  if (removed.meta.changes !== 1)
    return apiError(context, 404, "MEMBER_NOT_FOUND", "Member was not found");
  await removeGuildMembershipIndex(context.env, targetId, guildId);
  await refreshDirectoryMemberCount(context.env, guildId, guild.db);
  await appendGuildAudit(
    context.env,
    guildId,
    auth.id,
    "MEMBER_KICK",
    targetId,
  );
  return new Response(null, { status: 204 });
});

app.patch(
  "/api/v1/guilds/:guildId/members/:userId/timeout",
  async (context) => {
    const guildId = context.req.param("guildId");
    const targetId = context.req.param("userId");
    const auth = context.get("auth");
    if (
      !(await hasGuildPermission(
        context.env,
        guildId,
        null,
        auth.id,
        PermissionFlags.MODERATE_MEMBERS,
      )) ||
      !(await canModerateMember(context.env, guildId, auth.id, targetId))
    )
      return apiError(
        context,
        403,
        "MISSING_PERMISSIONS",
        "Moderate Members permission and a higher role are required",
      );
    const body = await context.req
      .json<{ until?: string | null; reason?: string }>()
      .catch(() => ({}) as { until?: string | null; reason?: string });
    const until = body.until === null ? null : new Date(body.until ?? "");
    if (
      until &&
      (Number.isNaN(until.getTime()) ||
        until.getTime() <= Date.now() ||
        until.getTime() > Date.now() + 28 * 24 * 60 * 60_000)
    )
      return apiError(
        context,
        400,
        "VALIDATION_ERROR",
        "Timeout must end within the next 28 days, or be null",
      );
    const guild = await guildDatabase(context.env, guildId);
    const updated = await guild.db
      .prepare(
        "UPDATE members SET timeout_until=?1 WHERE guild_id=?2 AND user_id=?3",
      )
      .bind(until?.toISOString() ?? null, guildId, targetId)
      .run();
    if (updated.meta.changes !== 1)
      return apiError(context, 404, "MEMBER_NOT_FOUND", "Member was not found");
    await appendGuildAudit(
      context.env,
      guildId,
      auth.id,
      until ? "MEMBER_TIMEOUT" : "MEMBER_TIMEOUT_CLEAR",
      targetId,
      body.reason ?? null,
      [{ key: "timeoutUntil", value: until?.toISOString() ?? null }],
    );
    return context.json({
      guildId,
      userId: targetId,
      timeoutUntil: until?.toISOString() ?? null,
    });
  },
);

app.put("/api/v1/guilds/:guildId/bans/:userId", async (context) => {
  const guildId = context.req.param("guildId");
  const targetId = context.req.param("userId");
  const auth = context.get("auth");
  if (
    !(await hasGuildPermission(
      context.env,
      guildId,
      null,
      auth.id,
      PermissionFlags.BAN_MEMBERS,
    )) ||
    !(await canModerateMember(context.env, guildId, auth.id, targetId))
  )
    return apiError(
      context,
      403,
      "MISSING_PERMISSIONS",
      "Ban Members permission and a higher role are required",
    );
  const body = await context.req
    .json<{ reason?: string; expiresAt?: string }>()
    .catch(() => ({}) as { reason?: string; expiresAt?: string });
  const expiresAt = body.expiresAt ? new Date(body.expiresAt) : null;
  if (
    expiresAt &&
    (Number.isNaN(expiresAt.getTime()) || expiresAt.getTime() <= Date.now())
  )
    return apiError(
      context,
      400,
      "VALIDATION_ERROR",
      "expiresAt must be in the future",
    );
  const guild = await guildDatabase(context.env, guildId);
  await guild.db.batch([
    guild.db
      .prepare(
        `INSERT INTO bans(guild_id,user_id,moderator_id,reason,expires_at,created_at)
         VALUES (?1,?2,?3,?4,?5,?6)
         ON CONFLICT(guild_id,user_id) DO UPDATE SET moderator_id=excluded.moderator_id,
           reason=excluded.reason,expires_at=excluded.expires_at,created_at=excluded.created_at`,
      )
      .bind(
        guildId,
        targetId,
        auth.id,
        body.reason?.slice(0, 512) ?? "No reason provided",
        expiresAt?.toISOString() ?? null,
        nowIso(),
      ),
    guild.db
      .prepare("DELETE FROM members WHERE guild_id=?1 AND user_id=?2")
      .bind(guildId, targetId),
  ]);
  await removeGuildMembershipIndex(context.env, targetId, guildId);
  await refreshDirectoryMemberCount(context.env, guildId, guild.db);
  await appendGuildAudit(
    context.env,
    guildId,
    auth.id,
    "MEMBER_BAN",
    targetId,
    body.reason ?? null,
  );
  return new Response(null, { status: 204 });
});

app.delete("/api/v1/guilds/:guildId/bans/:userId", async (context) => {
  const guildId = context.req.param("guildId");
  const auth = context.get("auth");
  if (
    !(await hasGuildPermission(
      context.env,
      guildId,
      null,
      auth.id,
      PermissionFlags.BAN_MEMBERS,
    ))
  )
    return apiError(
      context,
      403,
      "MISSING_PERMISSIONS",
      "Ban Members permission is required",
    );
  const guild = await guildDatabase(context.env, guildId);
  await guild.db
    .prepare("DELETE FROM bans WHERE guild_id=?1 AND user_id=?2")
    .bind(guildId, context.req.param("userId"))
    .run();
  await appendGuildAudit(
    context.env,
    guildId,
    auth.id,
    "MEMBER_UNBAN",
    context.req.param("userId"),
  );
  return new Response(null, { status: 204 });
});

app.get("/api/v1/guilds/:guildId/audit", async (context) => {
  const guildId = context.req.param("guildId");
  if (
    !(await hasGuildPermission(
      context.env,
      guildId,
      null,
      context.get("auth").id,
      PermissionFlags.VIEW_AUDIT_LOG,
    ))
  )
    return apiError(
      context,
      403,
      "MISSING_PERMISSIONS",
      "View Audit Log permission is required",
    );
  const guild = await guildDatabase(context.env, guildId);
  const result = await guild.db
    .prepare(
      `SELECT id,actor_id AS actorId,action,target_id AS targetId,reason,changes,created_at AS createdAt
         FROM guild_audit WHERE guild_id=?1 ORDER BY created_at DESC LIMIT 100`,
    )
    .bind(guildId)
    .all<{
      id: string;
      actorId: string;
      action: string;
      targetId: string | null;
      reason: string | null;
      changes: string;
      createdAt: string;
    }>();
  return context.json({
    entries: result.results.map((entry) => ({
      ...entry,
      changes: JSON.parse(entry.changes),
    })),
  });
});

app.get("/api/v1/guilds/:guildId/automod", async (context) => {
  const guildId = context.req.param("guildId");
  if (!(await isMember(context.env, guildId, context.get("auth").id)))
    return apiError(
      context,
      403,
      "MISSING_ACCESS",
      "Guild membership required",
    );
  const guild = await guildDatabase(context.env, guildId);
  const result = await guild.db
    .prepare(
      `SELECT id,name,trigger_type AS triggerType,trigger_metadata AS triggerMetadata,
              action_type AS actionType,enabled,creator_id AS creatorId
         FROM automod_rules WHERE guild_id=?1 ORDER BY created_at`,
    )
    .bind(guildId)
    .all<{
      id: string;
      name: string;
      triggerType: string;
      triggerMetadata: string;
      actionType: string;
      enabled: number;
      creatorId: string;
    }>();
  return context.json({
    rules: result.results.map((rule) => ({
      ...rule,
      triggerMetadata: JSON.parse(rule.triggerMetadata),
      enabled: Boolean(rule.enabled),
    })),
  });
});

app.post("/api/v1/guilds/:guildId/automod", async (context) => {
  const guildId = context.req.param("guildId");
  const auth = context.get("auth");
  if (
    !(await hasGuildPermission(
      context.env,
      guildId,
      null,
      auth.id,
      PermissionFlags.MANAGE_GUILD,
    ))
  )
    return apiError(
      context,
      403,
      "MISSING_PERMISSIONS",
      "Manage Guild permission is required",
    );
  const body = await context.req
    .json<{ name?: string; keywords?: string[]; action?: "block" | "flag" }>()
    .catch(
      () =>
        ({}) as {
          name?: string;
          keywords?: string[];
          action?: "block" | "flag";
        },
    );
  const keywords = [
    ...new Set(
      (body.keywords ?? []).map((word) => word.trim().toLocaleLowerCase()),
    ),
  ]
    .filter(Boolean)
    .slice(0, 100);
  if (
    !body.name ||
    body.name.length > 100 ||
    keywords.length === 0 ||
    !body.action
  )
    return apiError(
      context,
      400,
      "VALIDATION_ERROR",
      "name, keywords, and action are required",
    );
  if (keywords.some((word) => word.length > 100))
    return apiError(
      context,
      400,
      "VALIDATION_ERROR",
      "Keywords must be at most 100 characters",
    );
  const id = await generateId(context.env, guildId);
  const timestamp = nowIso();
  const guild = await guildDatabase(context.env, guildId);
  await guild.db
    .prepare(
      `INSERT INTO automod_rules(id,guild_id,name,trigger_type,trigger_metadata,action_type,creator_id,created_at,updated_at)
       VALUES (?1,?2,?3,'keyword',?4,?5,?6,?7,?7)`,
    )
    .bind(
      id,
      guildId,
      body.name,
      JSON.stringify({ keywords }),
      body.action,
      auth.id,
      timestamp,
    )
    .run();
  await appendGuildAudit(
    context.env,
    guildId,
    auth.id,
    "AUTOMOD_RULE_CREATE",
    id,
  );
  return context.json(
    {
      id,
      guildId,
      name: body.name,
      keywords,
      action: body.action,
      enabled: true,
    },
    201,
  );
});

app.delete("/api/v1/guilds/:guildId/automod/:ruleId", async (context) => {
  const guildId = context.req.param("guildId");
  const auth = context.get("auth");
  if (
    !(await hasGuildPermission(
      context.env,
      guildId,
      null,
      auth.id,
      PermissionFlags.MANAGE_GUILD,
    ))
  )
    return apiError(
      context,
      403,
      "MISSING_PERMISSIONS",
      "Manage Guild permission is required",
    );
  const guild = await guildDatabase(context.env, guildId);
  await guild.db
    .prepare("DELETE FROM automod_rules WHERE id=?1 AND guild_id=?2")
    .bind(context.req.param("ruleId"), guildId)
    .run();
  await appendGuildAudit(
    context.env,
    guildId,
    auth.id,
    "AUTOMOD_RULE_DELETE",
    context.req.param("ruleId"),
  );
  return new Response(null, { status: 204 });
});

app.post("/api/v1/reports", async (context) => {
  const auth = context.get("auth");
  const body = await context.req
    .json<{
      guildId?: string;
      targetType?: "user" | "message" | "channel";
      targetId?: string;
      reason?: string;
    }>()
    .catch(
      () =>
        ({}) as {
          guildId?: string;
          targetType?: "user" | "message" | "channel";
          targetId?: string;
          reason?: string;
        },
    );
  if (
    !body.guildId ||
    !body.targetType ||
    !body.targetId ||
    !body.reason ||
    body.reason.length > 1000
  )
    return apiError(
      context,
      400,
      "VALIDATION_ERROR",
      "Report fields are invalid",
    );
  if (!(await isMember(context.env, body.guildId, auth.id)))
    return apiError(
      context,
      403,
      "MISSING_ACCESS",
      "Guild membership required",
    );
  const id = await generateId(context.env, `${body.guildId}:report`);
  const guild = await guildDatabase(context.env, body.guildId);
  await guild.db
    .prepare(
      `INSERT INTO reports(id,guild_id,reporter_id,target_type,target_id,reason,created_at)
       VALUES (?1,?2,?3,?4,?5,?6,?7)`,
    )
    .bind(
      id,
      body.guildId,
      auth.id,
      body.targetType,
      body.targetId,
      body.reason,
      nowIso(),
    )
    .run();
  await appendGuildAudit(
    context.env,
    body.guildId,
    auth.id,
    "REPORT_CREATE",
    id,
  );
  return context.json({ id, status: "open" }, 201);
});

app.get("/api/v1/guilds/:guildId/reports", async (context) => {
  const guildId = context.req.param("guildId");
  if (
    !(await hasGuildPermission(
      context.env,
      guildId,
      null,
      context.get("auth").id,
      PermissionFlags.MANAGE_MESSAGES,
    ))
  )
    return apiError(
      context,
      403,
      "MISSING_PERMISSIONS",
      "Manage Messages permission is required",
    );
  const guild = await guildDatabase(context.env, guildId);
  const result = await guild.db
    .prepare(
      `SELECT id,reporter_id AS reporterId,target_type AS targetType,target_id AS targetId,
              reason,status,created_at AS createdAt,resolved_at AS resolvedAt
         FROM reports WHERE guild_id=?1 ORDER BY created_at DESC LIMIT 100`,
    )
    .bind(guildId)
    .all();
  return context.json({ reports: result.results });
});

app.patch("/api/v1/guilds/:guildId/reports/:reportId", async (context) => {
  const guildId = context.req.param("guildId");
  const auth = context.get("auth");
  if (
    !(await hasGuildPermission(
      context.env,
      guildId,
      null,
      auth.id,
      PermissionFlags.MANAGE_MESSAGES,
    ))
  )
    return apiError(
      context,
      403,
      "MISSING_PERMISSIONS",
      "Manage Messages permission is required",
    );
  const body = await context.req
    .json<{ status?: "resolved" | "dismissed"; reason?: string }>()
    .catch(
      () => ({}) as { status?: "resolved" | "dismissed"; reason?: string },
    );
  if (!body.status)
    return apiError(context, 400, "VALIDATION_ERROR", "status is required");
  const guild = await guildDatabase(context.env, guildId);
  const updated = await guild.db
    .prepare(
      "UPDATE reports SET status=?1,resolved_at=?2 WHERE id=?3 AND guild_id=?4 AND status='open'",
    )
    .bind(body.status, nowIso(), context.req.param("reportId"), guildId)
    .run();
  if (updated.meta.changes !== 1)
    return apiError(
      context,
      404,
      "REPORT_NOT_FOUND",
      "Open report was not found",
    );
  await appendGuildAudit(
    context.env,
    guildId,
    auth.id,
    "REPORT_RESOLVE",
    context.req.param("reportId"),
    body.reason ?? null,
    [{ key: "status", value: body.status }],
  );
  return context.json({
    id: context.req.param("reportId"),
    status: body.status,
  });
});

app.post("/api/v1/admin/bootstrap", async (context) => {
  const token = context.req.header("x-bootstrap-token");
  const auth = context.get("auth");
  const bootstrapToken = await getOptionalSecret(
    context.env,
    "ADMIN_BOOTSTRAP_TOKEN",
  );
  if (!bootstrapToken || token !== bootstrapToken)
    return apiError(
      context,
      403,
      "BOOTSTRAP_REJECTED",
      "Bootstrap token is invalid",
    );
  const count = await context.env.IDENTITY_DB.prepare(
    "SELECT count(*) AS count FROM instance_admins",
  ).first<{ count: number }>();
  if ((count?.count ?? 0) > 0)
    return apiError(
      context,
      409,
      "ALREADY_BOOTSTRAPPED",
      "An administrator already exists",
    );
  await context.env.IDENTITY_DB.prepare(
    "INSERT INTO instance_admins(user_id,granted_by,granted_at) VALUES (?1,'bootstrap',?2)",
  )
    .bind(auth.id, nowIso())
    .run();
  await context.env.IDENTITY_DB.prepare(
    "INSERT INTO admin_audit(id,actor_id,action,target_id,reason,created_at) VALUES (?1,?2,'ADMIN_BOOTSTRAP',?2,'Initial instance bootstrap',?3)",
  )
    .bind(await generateId(context.env, auth.id), auth.id, nowIso())
    .run();
  return context.json({ administrator: true }, 201);
});

app.get("/api/v1/admin/overview", async (context) => {
  const auth = context.get("auth");
  if (!(await isAdmin(context.env, auth.id)))
    return apiError(
      context,
      403,
      "ADMIN_REQUIRED",
      "Instance administrator access required",
    );
  const [users, sessions, bots, media, voice] =
    await context.env.IDENTITY_DB.batch([
      context.env.IDENTITY_DB.prepare(
        "SELECT count(*) AS value FROM users WHERE status='active'",
      ),
      context.env.IDENTITY_DB.prepare(
        "SELECT count(*) AS value FROM sessions WHERE revoked_at IS NULL AND expires_at>?1",
      ).bind(nowIso()),
      context.env.IDENTITY_DB.prepare(
        "SELECT count(*) AS value FROM bots WHERE enabled=1",
      ),
      context.env.IDENTITY_DB.prepare(
        "SELECT count(*) AS objects,coalesce(sum(size_bytes),0) AS bytes FROM media_objects WHERE state='ready'",
      ),
      context.env.IDENTITY_DB.prepare(
        `SELECT coalesce(sum(duration_seconds),0) AS participantSeconds,
              coalesce(sum(estimated_source_bytes),0) AS estimatedSourceBytes
         FROM voice_usage WHERE ended_at>=datetime('now','-30 days')`,
      ),
    ]);
  const settings = await context.env.IDENTITY_DB.prepare(
    "SELECT key,value FROM instance_config",
  ).all<{ key: string; value: string }>();
  const settingValues = Object.fromEntries(
    settings.results.map((entry) => [entry.key, entry.value]),
  );
  const voiceRow = (voice?.results[0] ?? {}) as {
    participantSeconds?: number;
    estimatedSourceBytes?: number;
  };
  const participantHours = Number(voiceRow.participantSeconds ?? 0) / 3600;
  const estimatedSourceGb = Number(voiceRow.estimatedSourceBytes ?? 0) / 1e9;
  const estimatedGbPerParticipantHour =
    participantHours > 0 ? estimatedSourceGb / participantHours : 0;
  const warningThreshold = Number(
    settingValues["voice.warning_gb_per_hour"] ?? "0.15",
  );
  return context.json({
    users: Number(
      (users?.results[0] as { value?: number } | undefined)?.value ?? 0,
    ),
    activeSessions: Number(
      (sessions?.results[0] as { value?: number } | undefined)?.value ?? 0,
    ),
    bots: Number(
      (bots?.results[0] as { value?: number } | undefined)?.value ?? 0,
    ),
    media: media?.results[0] ?? { objects: 0, bytes: 0 },
    voiceUsage30d: {
      participantHours,
      estimatedSourceGb,
      estimatedGbPerParticipantHour,
      warningThreshold,
      warning:
        participantHours > 0 &&
        estimatedGbPerParticipantHour >= warningThreshold,
    },
    shardPools: { identity: 1, social: 16, guild: 32, generation: 1 },
    settings: settingValues,
  });
});

app.patch("/api/v1/admin/settings", async (context) => {
  const auth = context.get("auth");
  if (!(await isAdmin(context.env, auth.id)))
    return apiError(
      context,
      403,
      "ADMIN_REQUIRED",
      "Instance administrator access required",
    );
  const body = await context.req
    .json<{ values?: Record<string, string>; reason?: string }>()
    .catch(() => ({}) as { values?: Record<string, string>; reason?: string });
  if (!body.reason || body.reason.length < 4)
    return apiError(
      context,
      400,
      "REASON_REQUIRED",
      "An administrative reason is required",
    );
  const allowed = new Set([
    "upload.file.bytes",
    "upload.daily_user.bytes",
    "upload.guild.bytes",
    "registration.enabled",
    "voice.warning_gb_per_hour",
    "export.retention_days",
  ]);
  const entries = Object.entries(body.values ?? {});
  if (
    entries.some(
      ([key, value]) =>
        !allowed.has(key) ||
        value.length > 128 ||
        !validInstanceSetting(key, value),
    )
  )
    return apiError(
      context,
      400,
      "SETTING_INVALID",
      "One or more settings are invalid",
    );
  const timestamp = nowIso();
  const statements = entries.map(([key, value]) =>
    context.env.IDENTITY_DB.prepare(
      "INSERT INTO instance_config(key,value,updated_by,updated_at) VALUES (?1,?2,?3,?4) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_by=excluded.updated_by,updated_at=excluded.updated_at",
    ).bind(key, value, auth.id, timestamp),
  );
  statements.push(
    context.env.IDENTITY_DB.prepare(
      "INSERT INTO admin_audit(id,actor_id,action,reason,metadata,created_at) VALUES (?1,?2,'INSTANCE_SETTINGS_UPDATE',?3,?4,?5)",
    ).bind(
      await generateId(context.env, auth.id),
      auth.id,
      body.reason,
      JSON.stringify({ keys: entries.map(([key]) => key) }),
      timestamp,
    ),
  );
  await context.env.IDENTITY_DB.batch(statements);
  return context.json({ updated: entries.map(([key]) => key) });
});

app.post("/api/v1/admin/shards/migrations", async (context) => {
  const auth = context.get("auth");
  if (!(await isAdmin(context.env, auth.id)))
    return apiError(
      context,
      403,
      "ADMIN_REQUIRED",
      "Instance administrator access required",
    );
  const body = await context.req
    .json<{
      domain?: "social" | "guild";
      bucket?: number;
      targetBinding?: string;
      reason?: string;
    }>()
    .catch(
      () =>
        ({}) as {
          domain?: "social" | "guild";
          bucket?: number;
          targetBinding?: string;
          reason?: string;
        },
    );
  const shardCount =
    body.domain === "social" ? 16 : body.domain === "guild" ? 32 : 0;
  const bindingPattern =
    body.domain === "social" ? /^SOCIAL_DB_\d{2}$/ : /^GUILD_DB_\d{2}$/;
  if (
    shardCount === 0 ||
    !Number.isInteger(body.bucket) ||
    body.bucket! < 0 ||
    body.bucket! >= shardCount ||
    !body.targetBinding ||
    !bindingPattern.test(body.targetBinding) ||
    !body.reason ||
    body.reason.trim().length < 4
  )
    return apiError(
      context,
      400,
      "VALIDATION_ERROR",
      "A valid domain, bucket, target binding, and administrative reason are required",
    );
  try {
    databaseBinding(context.env, body.targetBinding);
  } catch {
    return apiError(
      context,
      400,
      "SHARD_BINDING_UNAVAILABLE",
      "The target D1 binding is unavailable",
    );
  }
  const current = await context.env.IDENTITY_DB.prepare(
    `SELECT generation,binding_name,state FROM shard_map
      WHERE domain=?1 AND bucket=?2 AND state IN ('active','dual_write','cutover')
      ORDER BY generation DESC LIMIT 1`,
  )
    .bind(body.domain, body.bucket)
    .first<{ generation: number; binding_name: string; state: string }>();
  if (!current || current.state !== "active")
    return apiError(
      context,
      409,
      "SHARD_MIGRATION_ACTIVE",
      "The shard is unavailable or already migrating",
    );
  if (current.binding_name === body.targetBinding)
    return apiError(
      context,
      409,
      "SHARD_TARGET_UNCHANGED",
      "The target binding is already active",
    );
  const runId = await generateId(context.env, `${body.domain}:${body.bucket}`);
  const generation = current.generation + 1;
  const timestamp = nowIso();
  const inserted = await context.env.IDENTITY_DB.prepare(
    `INSERT INTO shard_migration_runs(
       id,domain,bucket,source_binding,target_binding,generation,requested_by,
       phase,copied_rows,error,created_at,updated_at
     )
     SELECT ?1,?2,?3,?4,?5,?6,?7,'queued',0,NULL,?8,?8
     WHERE NOT EXISTS (
       SELECT 1 FROM shard_migration_runs
        WHERE domain=?2 AND bucket=?3
          AND phase NOT IN ('complete','errored','aborted')
     )`,
  )
    .bind(
      runId,
      body.domain,
      body.bucket,
      current.binding_name,
      body.targetBinding,
      generation,
      auth.id,
      timestamp,
    )
    .run();
  if (inserted.meta.changes !== 1)
    return apiError(
      context,
      409,
      "SHARD_MIGRATION_ACTIVE",
      "A migration is already active for this shard",
    );
  try {
    await context.env.SHARD_MIGRATION.create({
      id: runId,
      params: {
        runId,
        domain: body.domain!,
        bucket: body.bucket!,
        generation,
        sourceBinding: current.binding_name,
        targetBinding: body.targetBinding!,
      },
    });
  } catch (cause) {
    await context.env.IDENTITY_DB.prepare(
      `UPDATE shard_migration_runs
          SET phase='errored',error=?1,updated_at=?2 WHERE id=?3`,
    )
      .bind(
        cause instanceof Error ? cause.message.slice(0, 2048) : String(cause),
        nowIso(),
        runId,
      )
      .run();
    throw cause;
  }
  await context.env.IDENTITY_DB.prepare(
    `INSERT INTO admin_audit(id,actor_id,action,target_id,reason,metadata,created_at)
     VALUES (?1,?2,'SHARD_MIGRATION_START',?3,?4,?5,?6)`,
  )
    .bind(
      await generateId(context.env, runId),
      auth.id,
      runId,
      body.reason.trim(),
      JSON.stringify({
        domain: body.domain,
        bucket: body.bucket,
        sourceBinding: current.binding_name,
        targetBinding: body.targetBinding,
        generation,
      }),
      timestamp,
    )
    .run();
  return context.json({ id: runId, phase: "queued", generation }, 202);
});

app.get("/api/v1/admin/shards/migrations/:runId", async (context) => {
  const auth = context.get("auth");
  if (!(await isAdmin(context.env, auth.id)))
    return apiError(
      context,
      403,
      "ADMIN_REQUIRED",
      "Instance administrator access required",
    );
  const runId = context.req.param("runId");
  const run = await context.env.IDENTITY_DB.prepare(
    `SELECT id,domain,bucket,source_binding AS sourceBinding,
            target_binding AS targetBinding,generation,requested_by AS requestedBy,
            phase,copied_rows AS copiedRows,error,created_at AS createdAt,
            updated_at AS updatedAt
       FROM shard_migration_runs WHERE id=?1`,
  )
    .bind(runId)
    .first();
  if (!run)
    return apiError(
      context,
      404,
      "SHARD_MIGRATION_NOT_FOUND",
      "Shard migration was not found",
    );
  let workflow: unknown = null;
  try {
    const instance = await context.env.SHARD_MIGRATION.get(runId);
    workflow = await instance.status();
  } catch {
    // The D1 run remains the authoritative audit record after Workflow retention.
  }
  return context.json({ run, workflow });
});

app.post("/api/v1/admin/shards/migrations/:runId/abort", async (context) => {
  const auth = context.get("auth");
  if (!(await isAdmin(context.env, auth.id)))
    return apiError(
      context,
      403,
      "ADMIN_REQUIRED",
      "Instance administrator access required",
    );
  const body = await context.req
    .json<{ reason?: string }>()
    .catch(() => ({}) as { reason?: string });
  if (!body.reason || body.reason.trim().length < 4)
    return apiError(
      context,
      400,
      "REASON_REQUIRED",
      "An administrative reason is required",
    );
  const runId = context.req.param("runId");
  const run = await context.env.IDENTITY_DB.prepare(
    `SELECT domain,bucket,generation,phase FROM shard_migration_runs WHERE id=?1`,
  )
    .bind(runId)
    .first<{
      domain: "social" | "guild";
      bucket: number;
      generation: number;
      phase: string;
    }>();
  if (!run)
    return apiError(
      context,
      404,
      "SHARD_MIGRATION_NOT_FOUND",
      "Shard migration was not found",
    );
  if (["complete", "errored", "aborted"].includes(run.phase))
    return apiError(
      context,
      409,
      "SHARD_MIGRATION_TERMINAL",
      "A completed migration cannot be aborted",
    );
  try {
    const instance = await context.env.SHARD_MIGRATION.get(runId);
    await instance.terminate();
  } catch {
    return apiError(
      context,
      409,
      "SHARD_MIGRATION_TERMINAL",
      "The Workflow is no longer abortable; refresh its status",
    );
  }
  const timestamp = nowIso();
  const retired = await context.env.IDENTITY_DB.prepare(
    `UPDATE shard_map SET state='retired',updated_at=?1
      WHERE domain=?2 AND bucket=?3 AND generation=?4
        AND state IN ('dual_write','cutover')`,
  )
    .bind(timestamp, run.domain, run.bucket, run.generation)
    .run();
  if (retired.meta.changes === 0) {
    const mapping = await context.env.IDENTITY_DB.prepare(
      `SELECT state FROM shard_map
        WHERE domain=?1 AND bucket=?2 AND generation=?3`,
    )
      .bind(run.domain, run.bucket, run.generation)
      .first<{ state: string }>();
    if (mapping?.state === "active")
      return apiError(
        context,
        409,
        "SHARD_MIGRATION_STATE_CHANGED",
        "The target shard became active while the Workflow was terminating",
      );
  }
  await context.env.IDENTITY_DB.batch([
    context.env.IDENTITY_DB.prepare(
      `UPDATE shard_migration_runs SET phase='aborted',error=NULL,updated_at=?1
        WHERE id=?2`,
    ).bind(timestamp, runId),
    context.env.IDENTITY_DB.prepare(
      `INSERT INTO admin_audit(id,actor_id,action,target_id,reason,metadata,created_at)
       VALUES (?1,?2,'SHARD_MIGRATION_ABORT',?3,?4,'{}',?5)`,
    ).bind(
      await generateId(context.env, runId),
      auth.id,
      runId,
      body.reason.trim(),
      timestamp,
    ),
  ]);
  return context.json({ id: runId, phase: "aborted" });
});

app.get("/api/v1/oauth2/authorize", async (context) => {
  const clientId = context.req.query("client_id");
  const scopes = new Set(
    (context.req.query("scope") ?? "bot applications.commands")
      .split(/\s+/u)
      .filter(Boolean),
  );
  if (
    !clientId ||
    [...scopes].some(
      (scope) => !["bot", "applications.commands"].includes(scope),
    )
  )
    return apiError(
      context,
      400,
      "OAUTH_REQUEST_INVALID",
      "A valid client_id and Bot install scopes are required",
    );
  const application = await context.env.IDENTITY_DB.prepare(
    `SELECT a.id,a.name,a.description,b.user_id AS botUserId
       FROM applications a JOIN bots b ON b.application_id=a.id
      WHERE a.id=?1 AND b.enabled=1`,
  )
    .bind(clientId)
    .first<{
      id: string;
      name: string;
      description: string;
      botUserId: string;
    }>();
  if (!application)
    return apiError(
      context,
      404,
      "APPLICATION_NOT_FOUND",
      "Bot application was not found",
    );
  const social = await socialDatabase(context.env, context.get("auth").id);
  const memberships = await social.db
    .prepare("SELECT guild_id FROM guild_membership_index WHERE user_id=?1")
    .bind(context.get("auth").id)
    .all<{ guild_id: string }>();
  const guilds = [];
  for (const membership of memberships.results) {
    if (
      !(await isGuildOwner(
        context.env,
        membership.guild_id,
        context.get("auth").id,
      ))
    )
      continue;
    const guild = await guildDatabase(context.env, membership.guild_id);
    const row = await guild.db
      .prepare("SELECT id,name,icon_key AS icon FROM guilds WHERE id=?1")
      .bind(membership.guild_id)
      .first();
    if (row) guilds.push(row);
  }
  return context.json({
    application,
    scopes: [...scopes],
    permissions: context.req.query("permissions") ?? "0",
    requestedGuildId: context.req.query("guild_id") ?? null,
    guilds,
  });
});

app.get("/api/v1/applications", async (context) => {
  const result = await context.env.IDENTITY_DB.prepare(
    `SELECT a.id,a.name,a.description,a.created_at AS createdAt,b.user_id AS botUserId,b.intents,b.enabled
       FROM applications a LEFT JOIN bots b ON b.application_id=a.id WHERE a.owner_id=?1 ORDER BY a.created_at`,
  )
    .bind(context.get("auth").id)
    .all();
  return context.json({ applications: result.results });
});

app.post("/api/v1/applications", async (context) => {
  const auth = context.get("auth");
  const body = await context.req
    .json<{ name?: string; description?: string; intents?: string }>()
    .catch(
      () => ({}) as { name?: string; description?: string; intents?: string },
    );
  if (!body.name || body.name.length > 100)
    return apiError(
      context,
      400,
      "VALIDATION_ERROR",
      "Application name is required",
    );
  let intents: bigint;
  try {
    intents = BigInt(body.intents ?? "0");
  } catch {
    return apiError(
      context,
      400,
      "VALIDATION_ERROR",
      "intents must be a decimal string",
    );
  }
  const applicationId = await generateId(context.env, auth.id);
  const botUserId = await generateId(context.env, applicationId);
  const botToken = `cc.${applicationId}.${randomToken(40)}`;
  const syntheticEmail = `bot-${botUserId}@internal.invalid`;
  const timestamp = nowIso();
  await context.env.IDENTITY_DB.batch([
    context.env.IDENTITY_DB.prepare(
      "INSERT INTO users(id,email_ciphertext,email_lookup_hash,username,display_name,status,created_at,updated_at) VALUES (?1,?2,?3,?4,?5,'active',?6,?6)",
    ).bind(
      botUserId,
      await encryptString(
        syntheticEmail,
        await getSecret(context.env, "DATA_ENCRYPTION_KEY"),
      ),
      await hmac(
        syntheticEmail,
        await getSecret(context.env, "LOOKUP_HMAC_KEY"),
      ),
      `bot_${botUserId}`,
      body.name,
      timestamp,
    ),
    context.env.IDENTITY_DB.prepare(
      "INSERT INTO applications(id,owner_id,name,description,created_at) VALUES (?1,?2,?3,?4,?5)",
    ).bind(
      applicationId,
      auth.id,
      body.name,
      body.description ?? "",
      timestamp,
    ),
    context.env.IDENTITY_DB.prepare(
      "INSERT INTO bots(application_id,user_id,token_hash,public_key,intents) VALUES (?1,?2,?3,'',?4)",
    ).bind(
      applicationId,
      botUserId,
      await sha256(botToken),
      intents.toString(),
    ),
  ]);
  return context.json(
    {
      id: applicationId,
      botUserId,
      name: body.name,
      token: botToken,
      intents: intents.toString(),
    },
    201,
  );
});

app.post("/api/v1/guilds/:guildId/bots/:applicationId", async (context) => {
  const auth = context.get("auth");
  const guildId = context.req.param("guildId");
  if (!(await isGuildOwner(context.env, guildId, auth.id)))
    return apiError(
      context,
      403,
      "MISSING_PERMISSIONS",
      "Only the guild owner can install bots",
    );
  const body = await context.req
    .json<{ permissions?: string }>()
    .catch(() => ({}) as { permissions?: string });
  const permissions = parsePermissionBits(body.permissions ?? "0");
  if (permissions === null)
    return apiError(
      context,
      400,
      "VALIDATION_ERROR",
      "permissions must be a supported decimal bitfield",
    );
  const application = await context.env.IDENTITY_DB.prepare(
    "SELECT b.user_id,a.name FROM applications a JOIN bots b ON b.application_id=a.id WHERE a.id=?1 AND b.enabled=1",
  )
    .bind(context.req.param("applicationId"))
    .first<{ user_id: string; name: string }>();
  if (!application)
    return apiError(
      context,
      404,
      "APPLICATION_NOT_FOUND",
      "Bot application was not found",
    );
  const guild = await guildDatabase(context.env, guildId);
  const timestamp = nowIso();
  const rolePosition = await guild.db
    .prepare(
      "SELECT coalesce(max(position),0)+1 AS value FROM roles WHERE guild_id=?1",
    )
    .bind(guildId)
    .first<{ value: number }>();
  await guild.db.batch([
    guild.db
      .prepare(
        `INSERT INTO roles(id,guild_id,name,permissions,position,color,managed,created_at)
         VALUES (?1,?2,?3,?4,?5,0,1,?6)
         ON CONFLICT(id) DO UPDATE SET name=excluded.name,
           permissions=excluded.permissions,managed=1`,
      )
      .bind(
        application.user_id,
        guildId,
        application.name,
        permissions.toString(),
        rolePosition?.value ?? 1,
        timestamp,
      ),
    guild.db
      .prepare(
        `INSERT INTO members(guild_id,user_id,role_ids,joined_at)
         VALUES (?1,?2,?3,?4)
         ON CONFLICT(guild_id,user_id) DO UPDATE SET role_ids=excluded.role_ids`,
      )
      .bind(
        guildId,
        application.user_id,
        JSON.stringify([guildId, application.user_id]),
        timestamp,
      ),
  ]);
  await context.env.IDENTITY_DB.prepare(
    `INSERT INTO bot_guild_installs(application_id,guild_id,bot_user_id,permissions,installed_by,installed_at)
     VALUES (?1,?2,?3,?4,?5,?6)
     ON CONFLICT(application_id,guild_id) DO UPDATE SET
       bot_user_id=excluded.bot_user_id,permissions=excluded.permissions,
       installed_by=excluded.installed_by,
       installed_at=excluded.installed_at`,
  )
    .bind(
      context.req.param("applicationId"),
      guildId,
      application.user_id,
      permissions.toString(),
      auth.id,
      timestamp,
    )
    .run();
  return context.json(
    {
      installed: true,
      botUserId: application.user_id,
      roleId: application.user_id,
      permissions: permissions.toString(),
    },
    201,
  );
});

app.post("/api/v1/interactions", async (context) => {
  const auth = context.get("auth");
  const body = await context.req
    .json<{
      applicationId?: string;
      guildId?: string;
      channelId?: string;
      type?: 2 | 3 | 5;
      commandId?: string;
      data?: Record<string, unknown>;
      message?: Record<string, unknown>;
    }>()
    .catch(() => null);
  const interactionType = body?.type ?? 2;
  if (
    !body?.applicationId ||
    !body.channelId ||
    ![2, 3, 5].includes(interactionType) ||
    (interactionType === 2 && !body.commandId) ||
    (interactionType !== 2 && !body.data)
  )
    return apiError(
      context,
      400,
      "INTERACTION_INVALID",
      "Application, channel, type, and interaction data are required",
    );
  const channel = await accessibleChannel(context.env, body.channelId, auth.id);
  if (!channel)
    return apiError(context, 403, "MISSING_ACCESS", "Channel access required");
  const guildId = channel.guild_id.startsWith("dm:") ? null : channel.guild_id;
  if (body.guildId && body.guildId !== guildId)
    return apiError(
      context,
      400,
      "INTERACTION_GUILD_MISMATCH",
      "The channel does not belong to the requested guild",
    );
  if (
    !hasPermission(
      channel.permissions,
      PermissionFlags.USE_APPLICATION_COMMANDS,
    )
  )
    return apiError(
      context,
      403,
      "MISSING_PERMISSIONS",
      "Use Application Commands permission is required",
    );
  const installation = guildId
    ? await context.env.IDENTITY_DB.prepare(
        `SELECT bot_user_id FROM bot_guild_installs
          WHERE application_id=?1 AND guild_id=?2`,
      )
        .bind(body.applicationId, guildId)
        .first<{ bot_user_id: string }>()
    : null;
  if (!installation)
    return apiError(
      context,
      403,
      "APPLICATION_NOT_INSTALLED",
      "The application is not installed in this guild",
    );
  let interactionData = body.data ?? {};
  if (interactionType === 2) {
    const command = await context.env.IDENTITY_DB.prepare(
      `SELECT id,type,payload_json FROM application_commands
        WHERE id=?1 AND application_id=?2
          AND (guild_id IS ?3 OR guild_id IS NULL)
        ORDER BY guild_id IS NOT NULL DESC LIMIT 1`,
    )
      .bind(body.commandId, body.applicationId, guildId)
      .first<{ id: string; type: number; payload_json: string }>();
    if (!command)
      return apiError(
        context,
        404,
        "COMMAND_NOT_FOUND",
        "Application command was not found",
      );
    const payload = JSON.parse(command.payload_json) as DiscordCommandInput;
    interactionData = {
      id: command.id,
      name: payload.name,
      type: command.type,
      options: Array.isArray(body.data?.options) ? body.data.options : [],
    };
  }
  const interactionId = await generateId(context.env, auth.id);
  const token = randomToken(48);
  const timestamp = nowIso();
  const expiresAt = new Date(Date.now() + 15 * 60_000).toISOString();
  const member = guildId
    ? await interactionMember(context.env, guildId, auth.id)
    : null;
  const event = {
    id: interactionId,
    application_id: body.applicationId,
    type: interactionType,
    data: interactionData,
    guild_id: guildId ?? undefined,
    channel_id: channel.id,
    member: member ?? undefined,
    user: guildId ? undefined : await discordUser(context.env, auth.id),
    token,
    version: 1,
    message: body.message,
    app_permissions: channel.permissions.toString(),
    locale: "ja",
    guild_locale: guildId ? "ja" : undefined,
  };
  await context.env.IDENTITY_DB.prepare(
    `INSERT INTO interaction_tokens(
       id,token_hash,application_id,bot_user_id,user_id,guild_id,channel_id,
       interaction_type,request_json,expires_at,created_at
     ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)`,
  )
    .bind(
      interactionId,
      await sha256(token),
      body.applicationId,
      installation.bot_user_id,
      auth.id,
      guildId,
      channel.id,
      interactionType,
      JSON.stringify(event),
      expiresAt,
      timestamp,
    )
    .run();
  const delivery = await context.env.BOT_GATEWAY_SHARDS.get(
    context.env.BOT_GATEWAY_SHARDS.idFromName("0"),
  ).fetch("https://gateway.internal/dispatch", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      event: "INTERACTION_CREATE",
      data: event,
      targetBotIds: [installation.bot_user_id],
      requiredIntent: "0",
      guildId: guildId ?? undefined,
    }),
  });
  const delivered = (await delivery.json<{ delivered: number }>()).delivered;
  return context.json(
    { id: interactionId, state: "pending", delivered, expiresAt },
    202,
  );
});

app.get("/api/v1/interactions/:interactionId", async (context) => {
  const interaction = await context.env.IDENTITY_DB.prepare(
    `SELECT id,state,response_type,response_json,expires_at,responded_at
       FROM interaction_tokens WHERE id=?1 AND user_id=?2`,
  )
    .bind(context.req.param("interactionId"), context.get("auth").id)
    .first<{
      id: string;
      state: string;
      response_type: number | null;
      response_json: string | null;
      expires_at: string;
      responded_at: string | null;
    }>();
  if (!interaction)
    return apiError(
      context,
      404,
      "INTERACTION_NOT_FOUND",
      "Interaction was not found",
    );
  return context.json({
    id: interaction.id,
    state: interaction.state,
    responseType: interaction.response_type,
    response: interaction.response_json
      ? JSON.parse(interaction.response_json)
      : null,
    expiresAt: interaction.expires_at,
    respondedAt: interaction.responded_at,
  });
});

app.get("/api/v1/channels/:channelId/messages", async (context) => {
  const channel = await accessibleChannel(
    context.env,
    context.req.param("channelId"),
    context.get("auth").id,
  );
  if (!channel)
    return apiError(context, 403, "MISSING_ACCESS", "Channel access required");
  if (!hasPermission(channel.permissions, PermissionFlags.READ_MESSAGE_HISTORY))
    return apiError(
      context,
      403,
      "MISSING_PERMISSIONS",
      "Read Message History permission is required",
    );
  const params = new URL(context.req.url).searchParams;
  params.set("viewer", context.get("auth").id);
  return channelStub(context.env, channel.id).fetch(
    new Request(`https://do/messages?${params}`),
  );
});

app.post("/api/v1/channels/:channelId/messages", async (context) => {
  const auth = context.get("auth");
  const channel = await accessibleChannel(
    context.env,
    context.req.param("channelId"),
    auth.id,
  );
  if (!channel)
    return apiError(context, 403, "MISSING_ACCESS", "Channel access required");
  if (!hasPermission(channel.permissions, PermissionFlags.SEND_MESSAGES))
    return apiError(
      context,
      403,
      "MISSING_PERMISSIONS",
      "Send Messages permission is required",
    );
  if (channel.timeout_until && Date.parse(channel.timeout_until) > Date.now())
    return apiError(
      context,
      403,
      "MEMBER_TIMED_OUT",
      "You cannot send messages while timed out",
    );
  const parsed = CreateMessageSchema.safeParse(
    await context.req.json().catch(() => null),
  );
  if (!parsed.success)
    return apiError(
      context,
      400,
      "VALIDATION_ERROR",
      "Message payload is invalid",
      parsed.error.flatten(),
    );
  if (
    parsed.data.attachmentIds.length > 0 &&
    !hasPermission(channel.permissions, PermissionFlags.ATTACH_FILES)
  )
    return apiError(
      context,
      403,
      "MISSING_PERMISSIONS",
      "Attach Files permission is required",
    );
  if (
    parsed.data.poll &&
    !hasPermission(channel.permissions, PermissionFlags.SEND_POLLS)
  )
    return apiError(
      context,
      403,
      "MISSING_PERMISSIONS",
      "Send Polls permission is required",
    );
  const autoMod = channel.guild_id.startsWith("dm:")
    ? null
    : await evaluateAutoMod(context.env, channel.guild_id, parsed.data.content);
  if (autoMod?.action === "block") {
    await appendGuildAudit(
      context.env,
      channel.guild_id,
      auth.id,
      "AUTOMOD_BLOCK",
      autoMod.id,
    );
    return apiError(
      context,
      400,
      "AUTOMOD_BLOCKED",
      "Message was blocked by AutoMod",
    );
  }
  const id = await generateId(context.env, channel.id);
  const attachments = [];
  for (const attachmentId of parsed.data.attachmentIds) {
    const media = await context.env.IDENTITY_DB.prepare(
      "SELECT id,filename,content_type,size_bytes FROM media_objects WHERE id=?1 AND owner_id=?2 AND state='ready'",
    )
      .bind(attachmentId, auth.id)
      .first<{
        id: string;
        filename: string;
        content_type: string;
        size_bytes: number;
      }>();
    if (!media)
      return apiError(
        context,
        400,
        "ATTACHMENT_INVALID",
        "An attachment is unavailable or not owned by the sender",
      );
    attachments.push({
      id: media.id,
      filename: media.filename,
      contentType: media.content_type,
      size: media.size_bytes,
      url: `/api/v1/media/${media.id}`,
    });
  }
  const response = await channelStub(context.env, channel.id).fetch(
    new Request("https://do/messages", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        id,
        channelId: channel.id,
        authorId: auth.id,
        authorUsername: auth.username,
        authorDisplayName: auth.displayName,
        authorBot: false,
        content: parsed.data.content,
        createdAt: nowIso(),
        replyToId: parsed.data.replyToId ?? null,
        attachments,
        partitionKey: channel.guild_id,
        poll: parsed.data.poll,
        slowmodeSeconds: channel.slowmode_seconds,
        bypassSlowmode: hasPermission(
          channel.permissions,
          PermissionFlags.BYPASS_SLOWMODE,
        ),
      }),
    }),
  );
  if (response.ok) {
    await context.env.IDENTITY_DB.prepare(
      `INSERT INTO user_channel_activity(user_id,channel_id,partition_key,last_message_at)
       VALUES (?1,?2,?3,?4)
       ON CONFLICT(user_id,channel_id) DO UPDATE SET
         partition_key=excluded.partition_key,last_message_at=excluded.last_message_at`,
    )
      .bind(auth.id, channel.id, channel.guild_id, nowIso())
      .run();
    if (!channel.guild_id.startsWith("dm:")) {
      const guild = await guildDatabase(context.env, channel.guild_id);
      await guild.db
        .prepare("UPDATE channels SET last_message_id=?1 WHERE id=?2")
        .bind(id, channel.id)
        .run();
    }
    if (autoMod?.action === "flag")
      await appendGuildAudit(
        context.env,
        channel.guild_id,
        auth.id,
        "AUTOMOD_FLAG",
        id,
        null,
        [{ key: "ruleId", value: autoMod.id }],
      );
  }
  return response;
});

app.patch(
  "/api/v1/channels/:channelId/messages/:messageId",
  async (context) => {
    const auth = context.get("auth");
    const channel = await accessibleChannel(
      context.env,
      context.req.param("channelId"),
      auth.id,
    );
    if (!channel)
      return apiError(
        context,
        403,
        "MISSING_ACCESS",
        "Channel access required",
      );
    const body = await context.req
      .json<{ content?: string }>()
      .catch(() => ({}) as { content?: string });
    if (typeof body.content !== "string" || body.content.length > 4000)
      return apiError(
        context,
        400,
        "VALIDATION_ERROR",
        "content must be a string of at most 4000 characters",
      );
    return channelStub(context.env, channel.id).fetch(
      new Request(
        `https://do/messages/${encodeURIComponent(context.req.param("messageId"))}`,
        {
          method: "PATCH",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            actorId: auth.id,
            canManage: hasPermission(
              channel.permissions,
              PermissionFlags.MANAGE_MESSAGES,
            ),
            content: body.content,
            partitionKey: channel.guild_id,
          }),
        },
      ),
    );
  },
);

app.delete(
  "/api/v1/channels/:channelId/messages/:messageId",
  async (context) => {
    const auth = context.get("auth");
    const channel = await accessibleChannel(
      context.env,
      context.req.param("channelId"),
      auth.id,
    );
    if (!channel)
      return apiError(
        context,
        403,
        "MISSING_ACCESS",
        "Channel access required",
      );
    return channelStub(context.env, channel.id).fetch(
      new Request(
        `https://do/messages/${encodeURIComponent(context.req.param("messageId"))}`,
        {
          method: "DELETE",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            actorId: auth.id,
            canManage: hasPermission(
              channel.permissions,
              PermissionFlags.MANAGE_MESSAGES,
            ),
            partitionKey: channel.guild_id,
          }),
        },
      ),
    );
  },
);

app.on(
  ["PUT", "DELETE"],
  "/api/v1/channels/:channelId/messages/:messageId/reactions/:emoji",
  async (context) => {
    const auth = context.get("auth");
    const channel = await accessibleChannel(
      context.env,
      context.req.param("channelId"),
      auth.id,
    );
    if (!channel)
      return apiError(
        context,
        403,
        "MISSING_ACCESS",
        "Channel access required",
      );
    if (
      context.req.method === "PUT" &&
      !hasPermission(channel.permissions, PermissionFlags.ADD_REACTIONS)
    )
      return apiError(
        context,
        403,
        "MISSING_PERMISSIONS",
        "Add Reactions permission is required",
      );
    return channelStub(context.env, channel.id).fetch(
      new Request(
        `https://do/messages/${encodeURIComponent(context.req.param("messageId"))}/reactions/${encodeURIComponent(context.req.param("emoji"))}`,
        {
          method: context.req.method,
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            actorId: auth.id,
            partitionKey: channel.guild_id,
          }),
        },
      ),
    );
  },
);

app.on(
  ["PUT", "DELETE"],
  "/api/v1/channels/:channelId/pins/:messageId",
  async (context) => {
    const auth = context.get("auth");
    const channel = await accessibleChannel(
      context.env,
      context.req.param("channelId"),
      auth.id,
    );
    if (!channel)
      return apiError(
        context,
        403,
        "MISSING_ACCESS",
        "Channel access required",
      );
    const canPin =
      hasPermission(channel.permissions, PermissionFlags.PIN_MESSAGES) ||
      hasPermission(channel.permissions, PermissionFlags.MANAGE_MESSAGES);
    if (!canPin)
      return apiError(
        context,
        403,
        "MISSING_PERMISSIONS",
        "Pin Messages permission is required",
      );
    return channelStub(context.env, channel.id).fetch(
      new Request(
        `https://do/pins/${encodeURIComponent(context.req.param("messageId"))}`,
        {
          method: context.req.method,
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            canManage: true,
            partitionKey: channel.guild_id,
          }),
        },
      ),
    );
  },
);

app.on(
  ["PUT", "DELETE"],
  "/api/v1/channels/:channelId/polls/:messageId/answers/:answerId",
  async (context) => {
    const auth = context.get("auth");
    const channel = await accessibleChannel(
      context.env,
      context.req.param("channelId"),
      auth.id,
    );
    if (!channel)
      return apiError(
        context,
        403,
        "MISSING_ACCESS",
        "Channel access required",
      );
    return channelStub(context.env, channel.id).fetch(
      new Request(
        `https://do/polls/${encodeURIComponent(context.req.param("messageId"))}/answers/${encodeURIComponent(context.req.param("answerId"))}`,
        {
          method: context.req.method,
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ actorId: auth.id }),
        },
      ),
    );
  },
);

app.get("/api/v1/guilds/:guildId/search", async (context) => {
  const guildId = context.req.param("guildId");
  const auth = context.get("auth");
  if (!(await isMember(context.env, guildId, auth.id)))
    return apiError(
      context,
      403,
      "MISSING_ACCESS",
      "Guild membership required",
    );
  const query = context.req.query("q")?.trim() ?? "";
  if (query.length < 2 || query.length > 100)
    return apiError(
      context,
      400,
      "VALIDATION_ERROR",
      "Search query must be 2 to 100 characters",
    );
  const months = Array.from({ length: 12 }, (_, offset) => {
    const date = new Date();
    date.setUTCDate(1);
    date.setUTCMonth(date.getUTCMonth() - offset);
    return date.toISOString().slice(0, 7);
  });
  const partitions = await Promise.all(
    months.map(async (month) => {
      const stub = context.env.SEARCH_PARTITIONS.get(
        context.env.SEARCH_PARTITIONS.idFromName(`${guildId}:${month}`),
      );
      const response = await stub.fetch(
        `https://search/?q=${encodeURIComponent(query)}`,
      );
      const payload = await response.json<{
        messages: {
          message_id: string;
          channel_id: string;
          excerpt: string;
        }[];
      }>();
      return payload.messages.map((message) => ({ ...message, month }));
    }),
  );
  const candidates = partitions.flat().slice(0, 200);
  const channelAccess = new Map<string, boolean>();
  for (const channelId of new Set(
    candidates.map((message) => message.channel_id),
  ))
    channelAccess.set(
      channelId,
      Boolean(await accessibleChannel(context.env, channelId, auth.id)),
    );
  return context.json({
    messages: candidates
      .filter((message) => channelAccess.get(message.channel_id))
      .slice(0, 50)
      .map((message) => ({
        id: message.message_id,
        channelId: message.channel_id,
        excerpt: message.excerpt,
        month: message.month,
      })),
  });
});

app.all("/api/v1/channels/:channelId/stream", async (context) => {
  const auth = context.get("auth");
  const channel = await accessibleChannel(
    context.env,
    context.req.param("channelId"),
    auth.id,
  );
  if (!channel)
    return apiError(context, 403, "MISSING_ACCESS", "Channel access required");
  const url = new URL(context.req.url);
  url.searchParams.set("user", auth.id);
  return channelStub(context.env, channel.id).fetch(
    new Request(url, context.req.raw),
  );
});

app.get("/api/v1/gateway", (context) => {
  const auth = context.get("auth");
  return context.env.USER_SESSIONS.get(
    context.env.USER_SESSIONS.idFromName(auth.id),
  ).fetch(context.req.raw);
});

app.post("/api/v1/voice/:channelId/join", async (context) => {
  const auth = context.get("auth");
  const channel = await accessibleChannel(
    context.env,
    context.req.param("channelId"),
    auth.id,
  );
  if (
    !channel ||
    !["GUILD_VOICE", "GUILD_STAGE_VOICE"].includes(channel.type) ||
    !hasPermission(channel.permissions, PermissionFlags.CONNECT)
  )
    return apiError(
      context,
      403,
      "VOICE_ACCESS_DENIED",
      "Accessible voice channel required",
    );
  const parsed = VoiceJoinSchema.safeParse(
    await context.req.json().catch(() => ({})),
  );
  if (!parsed.success)
    return apiError(
      context,
      400,
      "VALIDATION_ERROR",
      "Voice state is invalid",
      parsed.error.flatten(),
    );
  return voiceStub(context.env, channel.id).fetch(
    new Request("https://do/join", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        channelId: channel.id,
        userId: auth.id,
        displayName: auth.displayName,
        ...parsed.data,
      }),
    }),
  );
});

app.all("/api/v1/voice/:channelId/control", async (context) => {
  const auth = context.get("auth");
  const channel = await accessibleChannel(
    context.env,
    context.req.param("channelId"),
    auth.id,
  );
  if (!channel)
    return apiError(
      context,
      403,
      "VOICE_ACCESS_DENIED",
      "Voice channel access required",
    );
  const url = new URL(context.req.url);
  url.searchParams.set("user", auth.id);
  return voiceStub(context.env, channel.id).fetch(
    new Request(url, context.req.raw),
  );
});

app.delete("/api/v1/voice/:channelId", async (context) => {
  const auth = context.get("auth");
  const url = new URL("https://do/leave");
  url.searchParams.set("user", auth.id);
  return voiceStub(context.env, context.req.param("channelId")).fetch(
    new Request(url, { method: "DELETE" }),
  );
});

app.post("/api/v1/realtime/sessions", async (context) => {
  const auth = context.get("auth");
  const realtimeToken = await getOptionalSecret(
    context.env,
    "REALTIME_API_TOKEN",
  );
  if (!context.env.REALTIME_APP_ID || !realtimeToken)
    return apiError(
      context,
      503,
      "REALTIME_NOT_CONFIGURED",
      "Cloudflare Realtime credentials are not configured",
    );
  const body = await context.req
    .json<{ channelId?: string }>()
    .catch(() => ({}) as { channelId?: string });
  if (!body.channelId)
    return apiError(
      context,
      400,
      "VOICE_CHANNEL_REQUIRED",
      "A voice channel is required",
    );
  const channel = await accessibleChannel(context.env, body.channelId, auth.id);
  if (
    !channel ||
    !["GUILD_VOICE", "GUILD_STAGE_VOICE"].includes(channel.type) ||
    !hasPermission(channel.permissions, PermissionFlags.CONNECT)
  )
    return apiError(
      context,
      403,
      "VOICE_ACCESS_DENIED",
      "Accessible voice channel required",
    );
  const response = await fetch(
    `https://rtc.live.cloudflare.com/v1/apps/${context.env.REALTIME_APP_ID}/sessions/new`,
    {
      method: "POST",
      headers: {
        authorization: `Bearer ${realtimeToken}`,
        "content-type": "application/json",
      },
      body: "{}",
    },
  );
  const responseText = await response.text();
  if (!response.ok)
    return new Response(responseText, {
      status: response.status,
      headers: { "content-type": "application/json" },
    });
  const session = JSON.parse(responseText) as { sessionId?: string };
  if (!session.sessionId)
    throw new Error("Cloudflare Realtime did not return a session ID");
  const registered = await voiceStub(context.env, channel.id).fetch(
    "https://do/session",
    {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ userId: auth.id, sessionId: session.sessionId }),
    },
  );
  if (!registered.ok)
    return apiError(
      context,
      409,
      "VOICE_JOIN_REQUIRED",
      "Join the voice room before creating a Realtime session",
    );
  return context.json(session);
});

app.post("/api/v1/realtime/sessions/:sessionId/tracks", async (context) => {
  const auth = context.get("auth");
  const realtimeToken = await getOptionalSecret(
    context.env,
    "REALTIME_API_TOKEN",
  );
  if (!context.env.REALTIME_APP_ID || !realtimeToken)
    return apiError(
      context,
      503,
      "REALTIME_NOT_CONFIGURED",
      "Cloudflare Realtime credentials are not configured",
    );
  const body = await context.req
    .json<{
      channelId?: string;
      sessionDescription?: { sdp?: string; type?: string };
      tracks?: Array<{
        location?: "local" | "remote";
        mid?: string | null;
        trackName?: string;
        sessionId?: string;
        kind?: "audio" | "video";
        label?: "microphone" | "camera" | "screen";
        simulcast?: {
          preferredRid?: string;
          priorityOrdering?: "none" | "asciibetical";
          ridNotAvailable?: "none" | "asciibetical";
        };
      }>;
    }>()
    .catch(() => null);
  if (!body || !body.channelId || !Array.isArray(body.tracks))
    return apiError(
      context,
      400,
      "REALTIME_TRACKS_INVALID",
      "A voice channel and tracks are required",
    );
  const channel = await accessibleChannel(context.env, body.channelId, auth.id);
  if (!channel)
    return apiError(
      context,
      403,
      "VOICE_ACCESS_DENIED",
      "Voice channel access required",
    );
  const sessionId = context.req.param("sessionId");
  const sessionCheckUrl = new URL("https://do/session");
  sessionCheckUrl.searchParams.set("user", auth.id);
  sessionCheckUrl.searchParams.set("session", sessionId);
  const sessionCheck = await voiceStub(context.env, channel.id)
    .fetch(sessionCheckUrl)
    .then((result) => result.json<{ present?: boolean }>());
  if (!sessionCheck.present)
    return apiError(
      context,
      403,
      "REALTIME_SESSION_DENIED",
      "The Realtime session does not belong to this voice participant",
    );
  const realtimeBody = {
    sessionDescription: body.sessionDescription,
    tracks: body.tracks.map((track) => ({
      location: track.location,
      mid: track.mid,
      trackName: track.trackName,
      sessionId: track.sessionId,
      simulcast: track.simulcast,
    })),
  };
  const response = await fetch(
    `https://rtc.live.cloudflare.com/v1/apps/${context.env.REALTIME_APP_ID}/sessions/${sessionId}/tracks/new`,
    {
      method: "POST",
      headers: {
        authorization: `Bearer ${realtimeToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify(realtimeBody),
    },
  );
  const responseText = await response.text();
  if (response.ok) {
    const published = body.tracks
      .filter(
        (track) =>
          track.location === "local" &&
          track.trackName &&
          track.kind &&
          track.label,
      )
      .map((track) => ({
        trackName: track.trackName!,
        kind: track.kind!,
        label: track.label!,
      }));
    if (published.length > 0)
      await voiceStub(context.env, channel.id).fetch("https://do/tracks", {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ userId: auth.id, sessionId, tracks: published }),
      });
  }
  return new Response(responseText, {
    status: response.status,
    headers: {
      "content-type":
        response.headers.get("content-type") ?? "application/json",
    },
  });
});

app.put("/api/v1/realtime/sessions/:sessionId/renegotiate", async (context) => {
  const auth = context.get("auth");
  const realtimeToken = await getOptionalSecret(
    context.env,
    "REALTIME_API_TOKEN",
  );
  if (!context.env.REALTIME_APP_ID || !realtimeToken)
    return apiError(
      context,
      503,
      "REALTIME_NOT_CONFIGURED",
      "Cloudflare Realtime credentials are not configured",
    );
  const body = await context.req
    .json<{
      channelId?: string;
      sessionDescription?: { sdp?: string; type?: string };
    }>()
    .catch(() => null);
  if (!body || !body.channelId || !body.sessionDescription)
    return apiError(
      context,
      400,
      "REALTIME_RENEGOTIATION_INVALID",
      "A voice channel and session description are required",
    );
  const channel = await accessibleChannel(context.env, body.channelId, auth.id);
  if (!channel)
    return apiError(
      context,
      403,
      "VOICE_ACCESS_DENIED",
      "Voice channel access required",
    );
  const sessionId = context.req.param("sessionId");
  if (!(await ownsRealtimeSession(context.env, channel.id, auth.id, sessionId)))
    return apiError(
      context,
      403,
      "REALTIME_SESSION_DENIED",
      "The Realtime session does not belong to this voice participant",
    );
  const response = await fetch(
    `https://rtc.live.cloudflare.com/v1/apps/${context.env.REALTIME_APP_ID}/sessions/${sessionId}/renegotiate`,
    {
      method: "PUT",
      headers: {
        authorization: `Bearer ${realtimeToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        sessionDescription: body.sessionDescription,
      }),
    },
  );
  return new Response(response.body, {
    status: response.status,
    headers: { "content-type": "application/json" },
  });
});

app.delete("/api/v1/realtime/sessions/:sessionId/tracks", async (context) => {
  const auth = context.get("auth");
  const body = await context.req
    .json<{ channelId?: string; trackNames?: string[]; mids?: string[] }>()
    .catch(
      () =>
        ({}) as {
          channelId?: string;
          trackNames?: string[];
          mids?: string[];
        },
    );
  if (!body.channelId || (!body.trackNames?.length && !body.mids?.length))
    return apiError(
      context,
      400,
      "REALTIME_TRACKS_INVALID",
      "A voice channel and track names are required",
    );
  const channel = await accessibleChannel(context.env, body.channelId, auth.id);
  if (!channel)
    return apiError(
      context,
      403,
      "VOICE_ACCESS_DENIED",
      "Voice channel access required",
    );
  const sessionId = context.req.param("sessionId");
  if (!(await ownsRealtimeSession(context.env, channel.id, auth.id, sessionId)))
    return apiError(
      context,
      403,
      "REALTIME_SESSION_DENIED",
      "The Realtime session does not belong to this voice participant",
    );
  if (body.mids?.length) {
    const realtimeToken = await getOptionalSecret(
      context.env,
      "REALTIME_API_TOKEN",
    );
    if (!context.env.REALTIME_APP_ID || !realtimeToken)
      return apiError(
        context,
        503,
        "REALTIME_NOT_CONFIGURED",
        "Cloudflare Realtime credentials are not configured",
      );
    const closed = await fetch(
      `https://rtc.live.cloudflare.com/v1/apps/${context.env.REALTIME_APP_ID}/sessions/${sessionId}/tracks/close`,
      {
        method: "PUT",
        headers: {
          authorization: `Bearer ${realtimeToken}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          tracks: body.mids.map((mid) => ({ mid })),
          force: true,
        }),
      },
    );
    if (!closed.ok)
      return new Response(closed.body, {
        status: closed.status,
        headers: { "content-type": "application/json" },
      });
  }
  if (body.trackNames?.length) {
    const response = await voiceStub(context.env, channel.id).fetch(
      "https://do/tracks",
      {
        method: "DELETE",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          userId: auth.id,
          sessionId,
          trackNames: body.trackNames,
        }),
      },
    );
    if (!response.ok)
      return apiError(
        context,
        403,
        "REALTIME_SESSION_DENIED",
        "The Realtime session does not belong to this voice participant",
      );
  }
  return new Response(null, { status: 204 });
});

app.post("/api/v1/uploads", async (context) => {
  const body = await context.req
    .json<{
      filename?: string;
      contentType?: string;
      size?: number;
      guildId?: string;
    }>()
    .catch(
      () =>
        ({}) as {
          filename?: string;
          contentType?: string;
          size?: number;
          guildId?: string;
        },
    );
  if (!body.filename || !body.contentType || !Number.isInteger(body.size))
    return apiError(
      context,
      400,
      "VALIDATION_ERROR",
      "filename, contentType, and integer size are required",
    );
  if (
    body.size! >
    (await configNumber(
      context.env,
      "upload.file.bytes",
      Number(context.env.UPLOAD_FILE_LIMIT_BYTES),
    ))
  )
    return apiError(
      context,
      413,
      "FILE_TOO_LARGE",
      "File exceeds the configured upload limit",
    );
  const auth = context.get("auth");
  if (body.guildId && !(await isMember(context.env, body.guildId, auth.id)))
    return apiError(
      context,
      403,
      "MISSING_ACCESS",
      "Guild membership is required for guild media",
    );
  const startOfDay = new Date();
  startOfDay.setUTCHours(0, 0, 0, 0);
  const daily = await context.env.IDENTITY_DB.prepare(
    "SELECT coalesce(sum(size_bytes),0) AS used FROM media_objects WHERE owner_id=?1 AND state IN ('pending','ready') AND created_at>=?2",
  )
    .bind(auth.id, startOfDay.toISOString())
    .first<{ used: number }>();
  if (
    (daily?.used ?? 0) + body.size! >
    (await configNumber(
      context.env,
      "upload.daily_user.bytes",
      Number(context.env.UPLOAD_DAILY_USER_LIMIT_BYTES),
    ))
  )
    return apiError(
      context,
      429,
      "DAILY_UPLOAD_LIMIT",
      "Daily upload quota exceeded",
    );
  if (body.guildId) {
    const guild = await context.env.IDENTITY_DB.prepare(
      "SELECT coalesce(sum(size_bytes),0) AS used FROM media_objects WHERE guild_id=?1 AND state='ready'",
    )
      .bind(body.guildId)
      .first<{ used: number }>();
    if (
      (guild?.used ?? 0) + body.size! >
      (await configNumber(
        context.env,
        "upload.guild.bytes",
        Number(context.env.UPLOAD_GUILD_LIMIT_BYTES),
      ))
    )
      return apiError(
        context,
        413,
        "GUILD_STORAGE_LIMIT",
        "Guild storage quota exceeded",
      );
  }
  const id = await generateId(context.env, context.get("auth").id);
  const objectKey = `attachments/${context.get("auth").id}/${id}`;
  await context.env.IDENTITY_DB.prepare(
    "INSERT INTO media_objects(id, owner_id, guild_id, object_key, filename, content_type, size_bytes, created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
  )
    .bind(
      id,
      context.get("auth").id,
      body.guildId ?? null,
      objectKey,
      body.filename,
      body.contentType,
      body.size,
      nowIso(),
      new Date(Date.now() + 60 * 60_000).toISOString(),
    )
    .run();
  return context.json(
    { id, uploadUrl: `/api/v1/uploads/${id}/content`, expiresIn: 3600 },
    201,
  );
});

app.put("/api/v1/uploads/:id/content", async (context) => {
  const auth = context.get("auth");
  const media = await context.env.IDENTITY_DB.prepare(
    "SELECT object_key, content_type, size_bytes FROM media_objects WHERE id=?1 AND owner_id=?2 AND state='pending' AND expires_at>?3",
  )
    .bind(context.req.param("id"), auth.id, nowIso())
    .first<{ object_key: string; content_type: string; size_bytes: number }>();
  if (!media)
    return apiError(
      context,
      404,
      "UPLOAD_NOT_FOUND",
      "Pending upload was not found",
    );
  const contentLength = Number(context.req.header("content-length") ?? -1);
  if (contentLength !== media.size_bytes)
    return apiError(
      context,
      400,
      "SIZE_MISMATCH",
      "Content-Length does not match declared size",
    );
  const bytes = await context.req.arrayBuffer();
  if (bytes.byteLength !== media.size_bytes)
    return apiError(
      context,
      400,
      "SIZE_MISMATCH",
      "Body size does not match declared size",
    );
  if (!mimeMatches(media.content_type, new Uint8Array(bytes)))
    return apiError(
      context,
      400,
      "MIME_MISMATCH",
      "File signature does not match declared content type",
    );
  await context.env.MEDIA.put(media.object_key, bytes, {
    httpMetadata: { contentType: media.content_type },
    customMetadata: { ownerId: auth.id },
  });
  await context.env.IDENTITY_DB.prepare(
    "UPDATE media_objects SET state='ready', expires_at=NULL WHERE id=?1",
  )
    .bind(context.req.param("id"))
    .run();
  return new Response(null, { status: 204 });
});

app.get("/api/v1/media/:id", async (context) => {
  const auth = context.get("auth");
  const media = await context.env.IDENTITY_DB.prepare(
    "SELECT owner_id,guild_id,object_key,filename,content_type FROM media_objects WHERE id=?1 AND state='ready'",
  )
    .bind(context.req.param("id"))
    .first<{
      owner_id: string;
      guild_id: string | null;
      object_key: string;
      filename: string;
      content_type: string;
    }>();
  if (!media)
    return apiError(context, 404, "MEDIA_NOT_FOUND", "Media was not found");
  if (
    media.owner_id !== auth.id &&
    (!media.guild_id || !(await isMember(context.env, media.guild_id, auth.id)))
  )
    return apiError(context, 403, "MISSING_ACCESS", "Media access denied");
  const object = await context.env.MEDIA.get(media.object_key);
  if (!object)
    return apiError(
      context,
      404,
      "MEDIA_NOT_FOUND",
      "Media object was not found",
    );
  return new Response(object.body, {
    headers: {
      "content-type": media.content_type,
      "content-disposition": `inline; filename*=UTF-8''${encodeURIComponent(media.filename)}`,
      "cache-control": "private, max-age=300",
      "x-content-type-options": "nosniff",
    },
  });
});

app.get("/api/v10/gateway", async (context) => {
  if (context.req.header("upgrade")?.toLowerCase() !== "websocket")
    return context.json({
      url: `${context.env.PUBLIC_ORIGIN.replace(/^http/, "ws")}/api/v10/gateway`,
    });
  const shard = context.req.query("shard") ?? "0";
  return await context.env.BOT_GATEWAY_SHARDS.get(
    context.env.BOT_GATEWAY_SHARDS.idFromName(shard),
  ).fetch(context.req.raw);
});
app.get("/api/v10/gateway/bot", async (context) => {
  if (!(await authenticateBot(context.env, context.req.raw)))
    return discordError(context, 401, 0, "401: Unauthorized");
  return context.json({
    url: `${context.env.PUBLIC_ORIGIN.replace(/^http/, "ws")}/api/v10/gateway`,
    shards: 1,
    session_start_limit: {
      total: 1000,
      remaining: 1000,
      reset_after: 86_400_000,
      max_concurrency: 1,
    },
  });
});
app.get("/api/v10/users/@me", async (context) => {
  const bot = await authenticateBot(context.env, context.req.raw);
  if (!bot) return discordError(context, 401, 0, "401: Unauthorized");
  return context.json({
    id: bot.userId,
    username: bot.username,
    discriminator: "0000",
    avatar: null,
    bot: true,
    system: false,
    flags: 0,
  });
});
app.post("/api/v10/voice/:channelId/join", async (context) => {
  const bot = await authenticateBot(context.env, context.req.raw);
  if (!bot) return discordError(context, 401, 0, "401: Unauthorized");
  const channel = await accessibleChannel(
    context.env,
    context.req.param("channelId"),
    bot.userId,
  );
  if (
    !channel ||
    !["GUILD_VOICE", "GUILD_STAGE_VOICE"].includes(channel.type) ||
    !hasPermission(channel.permissions, PermissionFlags.CONNECT)
  )
    return discordError(context, 403, 50013, "Missing Permissions");
  return voiceStub(context.env, channel.id).fetch(
    new Request("https://do/join", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        userId: bot.userId,
        displayName: bot.username,
        muted: false,
        deafened: false,
        camera: false,
      }),
    }),
  );
});
app.get("/api/v10/oauth2/applications/@me", async (context) => {
  const bot = await authenticateBot(context.env, context.req.raw);
  if (!bot) return discordError(context, 401, 0, "401: Unauthorized");
  const application = await context.env.IDENTITY_DB.prepare(
    "SELECT id,name,description,owner_id FROM applications WHERE id=?1",
  )
    .bind(bot.applicationId)
    .first<{
      id: string;
      name: string;
      description: string;
      owner_id: string;
    }>();
  if (!application)
    return discordError(context, 404, 10002, "Unknown Application");
  return context.json(
    {
      id: application.id,
      name: application.name,
      icon: null,
      description: application.description,
      bot_public: true,
      bot_require_code_grant: false,
      verify_key: "",
      flags: 0,
      owner: await discordUser(context.env, application.owner_id),
      approximate_guild_count: await context.env.IDENTITY_DB.prepare(
        "SELECT count(*) AS value FROM bot_guild_installs WHERE application_id=?1",
      )
        .bind(application.id)
        .first<{ value: number }>()
        .then((row) => Number(row?.value ?? 0)),
    },
    200,
    discordRateLimitHeaders(),
  );
});
app.delete("/api/v10/voice/:channelId", async (context) => {
  const bot = await authenticateBot(context.env, context.req.raw);
  if (!bot) return discordError(context, 401, 0, "401: Unauthorized");
  const channel = await accessibleChannel(
    context.env,
    context.req.param("channelId"),
    bot.userId,
  );
  if (!channel) return discordError(context, 403, 50001, "Missing Access");
  const url = new URL("https://do/leave");
  url.searchParams.set("user", bot.userId);
  return voiceStub(context.env, channel.id).fetch(
    new Request(url, { method: "DELETE" }),
  );
});
app.post("/api/v10/voice/:channelId/sessions", async (context) => {
  const bot = await authenticateBot(context.env, context.req.raw);
  if (!bot) return discordError(context, 401, 0, "401: Unauthorized");
  const channel = await accessibleChannel(
    context.env,
    context.req.param("channelId"),
    bot.userId,
  );
  if (
    !channel ||
    !["GUILD_VOICE", "GUILD_STAGE_VOICE"].includes(channel.type) ||
    !hasPermission(channel.permissions, PermissionFlags.CONNECT)
  )
    return discordError(context, 403, 50013, "Missing Permissions");
  return createDiscordVoiceSession(context.env, channel.id, bot.userId);
});
app.post(
  "/api/v10/voice/:channelId/sessions/:sessionId/tracks",
  async (context) => {
    const bot = await authenticateBot(context.env, context.req.raw);
    if (!bot) return discordError(context, 401, 0, "401: Unauthorized");
    const channel = await accessibleChannel(
      context.env,
      context.req.param("channelId"),
      bot.userId,
    );
    if (!channel) return discordError(context, 403, 50001, "Missing Access");
    const body = await context.req
      .json<DiscordRealtimeTracks>()
      .catch(() => null);
    if (!body || !Array.isArray(body.tracks))
      return discordError(context, 400, 50035, "Invalid Form Body");
    return updateDiscordVoiceTracks(
      context.env,
      channel,
      bot.userId,
      context.req.param("sessionId"),
      body,
    );
  },
);
app.put(
  "/api/v10/voice/:channelId/sessions/:sessionId/renegotiate",
  async (context) => {
    const bot = await authenticateBot(context.env, context.req.raw);
    if (!bot) return discordError(context, 401, 0, "401: Unauthorized");
    const channel = await accessibleChannel(
      context.env,
      context.req.param("channelId"),
      bot.userId,
    );
    if (!channel) return discordError(context, 403, 50001, "Missing Access");
    const body = await context.req
      .json<{ sessionDescription?: { sdp?: string; type?: string } }>()
      .catch(() => null);
    if (!body?.sessionDescription)
      return discordError(context, 400, 50035, "Invalid Form Body");
    return renegotiateDiscordVoiceSession(
      context.env,
      channel.id,
      bot.userId,
      context.req.param("sessionId"),
      body.sessionDescription,
    );
  },
);
app.delete(
  "/api/v10/voice/:channelId/sessions/:sessionId/tracks",
  async (context) => {
    const bot = await authenticateBot(context.env, context.req.raw);
    if (!bot) return discordError(context, 401, 0, "401: Unauthorized");
    const channel = await accessibleChannel(
      context.env,
      context.req.param("channelId"),
      bot.userId,
    );
    if (!channel) return discordError(context, 403, 50001, "Missing Access");
    const body = await context.req
      .json<{ trackNames?: string[]; mids?: string[] }>()
      .catch(() => null);
    if (!body || (!body.trackNames?.length && !body.mids?.length))
      return discordError(context, 400, 50035, "Invalid Form Body");
    return closeDiscordVoiceTracks(
      context.env,
      channel.id,
      bot.userId,
      context.req.param("sessionId"),
      body,
    );
  },
);
app.post("/api/v10/channels/:channelId/threads", async (context) => {
  const bot = await authenticateBot(context.env, context.req.raw);
  if (!bot) return discordError(context, 401, 0, "401: Unauthorized");
  const parent = await accessibleChannel(
    context.env,
    context.req.param("channelId"),
    bot.userId,
  );
  if (!parent) return discordError(context, 403, 50001, "Missing Access");
  const body = await context.req.json<DiscordThreadInput>().catch(() => null);
  return createDiscordThread(context, parent, bot, body);
});
app.post(
  "/api/v10/channels/:channelId/messages/:messageId/threads",
  async (context) => {
    const bot = await authenticateBot(context.env, context.req.raw);
    if (!bot) return discordError(context, 401, 0, "401: Unauthorized");
    const parent = await accessibleChannel(
      context.env,
      context.req.param("channelId"),
      bot.userId,
    );
    if (!parent) return discordError(context, 403, 50001, "Missing Access");
    const body = await context.req.json<DiscordThreadInput>().catch(() => null);
    return createDiscordThread(context, parent, bot, body);
  },
);
app.on(
  ["PUT", "DELETE"],
  "/api/v10/channels/:channelId/thread-members/@me",
  async (context) => {
    const bot = await authenticateBot(context.env, context.req.raw);
    if (!bot) return discordError(context, 401, 0, "401: Unauthorized");
    const thread = await accessibleChannel(
      context.env,
      context.req.param("channelId"),
      bot.userId,
    );
    if (!thread || !thread.type.includes("THREAD"))
      return discordError(context, 404, 10003, "Unknown Channel");
    const guild = await guildDatabase(context.env, thread.guild_id);
    if (context.req.method === "DELETE")
      await guild.db
        .prepare(
          "DELETE FROM thread_members WHERE channel_id=?1 AND user_id=?2",
        )
        .bind(thread.id, bot.userId)
        .run();
    else
      await guild.db
        .prepare(
          `INSERT INTO thread_members(channel_id,user_id,joined_at)
           VALUES (?1,?2,?3) ON CONFLICT(channel_id,user_id) DO NOTHING`,
        )
        .bind(thread.id, bot.userId, nowIso())
        .run();
    return new Response(null, {
      status: 204,
      headers: discordRateLimitHeaders(),
    });
  },
);
app.get("/api/v10/channels/:channelId/thread-members", async (context) => {
  const bot = await authenticateBot(context.env, context.req.raw);
  if (!bot) return discordError(context, 401, 0, "401: Unauthorized");
  const thread = await accessibleChannel(
    context.env,
    context.req.param("channelId"),
    bot.userId,
  );
  if (!thread || !thread.type.includes("THREAD"))
    return discordError(context, 404, 10003, "Unknown Channel");
  const guild = await guildDatabase(context.env, thread.guild_id);
  const members = await guild.db
    .prepare(
      "SELECT user_id,joined_at,flags FROM thread_members WHERE channel_id=?1 ORDER BY joined_at LIMIT 100",
    )
    .bind(thread.id)
    .all<{ user_id: string; joined_at: string; flags: number }>();
  return context.json(
    members.results.map((member) => ({
      id: thread.id,
      user_id: member.user_id,
      join_timestamp: member.joined_at,
      flags: member.flags,
    })),
    200,
    discordRateLimitHeaders(),
  );
});
app.post("/api/v10/stage-instances", async (context) => {
  const bot = await authenticateBot(context.env, context.req.raw);
  if (!bot) return discordError(context, 401, 0, "401: Unauthorized");
  const body = await context.req
    .json<{
      channel_id?: string;
      topic?: string;
      privacy_level?: number;
    }>()
    .catch(() => null);
  if (
    !body?.channel_id ||
    !body.topic ||
    body.topic.length > 120 ||
    (body.privacy_level !== undefined && body.privacy_level !== 2)
  )
    return discordError(context, 400, 50035, "Invalid Form Body");
  const channel = await accessibleChannel(
    context.env,
    body.channel_id,
    bot.userId,
  );
  if (
    !channel ||
    channel.type !== "GUILD_STAGE_VOICE" ||
    !hasPermission(channel.permissions, PermissionFlags.MANAGE_CHANNELS)
  )
    return discordError(context, 403, 50013, "Missing Permissions");
  const guild = await guildDatabase(context.env, channel.guild_id);
  const timestamp = nowIso();
  try {
    await guild.db
      .prepare(
        `INSERT INTO stage_instances(channel_id,guild_id,topic,privacy_level,created_by,created_at,updated_at)
         VALUES (?1,?2,?3,2,?4,?5,?5)`,
      )
      .bind(channel.id, channel.guild_id, body.topic, bot.userId, timestamp)
      .run();
  } catch {
    return discordError(context, 409, 150006, "The Stage is already open");
  }
  return context.json(
    discordStageInstance(channel.id, channel.guild_id, body.topic),
    201,
    discordRateLimitHeaders(),
  );
});
app.on(
  ["GET", "PATCH", "DELETE"],
  "/api/v10/stage-instances/:channelId",
  async (context) => {
    const bot = await authenticateBot(context.env, context.req.raw);
    if (!bot) return discordError(context, 401, 0, "401: Unauthorized");
    const channel = await accessibleChannel(
      context.env,
      context.req.param("channelId"),
      bot.userId,
    );
    if (!channel || channel.type !== "GUILD_STAGE_VOICE")
      return discordError(context, 404, 10067, "Unknown Stage Instance");
    const guild = await guildDatabase(context.env, channel.guild_id);
    const stage = await guild.db
      .prepare(
        "SELECT topic,privacy_level FROM stage_instances WHERE channel_id=?1",
      )
      .bind(channel.id)
      .first<{ topic: string; privacy_level: number }>();
    if (!stage)
      return discordError(context, 404, 10067, "Unknown Stage Instance");
    if (context.req.method === "GET")
      return context.json(
        discordStageInstance(channel.id, channel.guild_id, stage.topic),
        200,
        discordRateLimitHeaders(),
      );
    if (!hasPermission(channel.permissions, PermissionFlags.MANAGE_CHANNELS))
      return discordError(context, 403, 50013, "Missing Permissions");
    if (context.req.method === "DELETE") {
      await guild.db
        .prepare("DELETE FROM stage_instances WHERE channel_id=?1")
        .bind(channel.id)
        .run();
      return new Response(null, {
        status: 204,
        headers: discordRateLimitHeaders(),
      });
    }
    const body = await context.req
      .json<{ topic?: string; privacy_level?: number }>()
      .catch(() => null);
    if (
      !body ||
      (body.topic !== undefined &&
        (body.topic.length < 1 || body.topic.length > 120)) ||
      (body.privacy_level !== undefined && body.privacy_level !== 2)
    )
      return discordError(context, 400, 50035, "Invalid Form Body");
    const topic = body.topic ?? stage.topic;
    await guild.db
      .prepare(
        "UPDATE stage_instances SET topic=?1,privacy_level=2,updated_at=?2 WHERE channel_id=?3",
      )
      .bind(topic, nowIso(), channel.id)
      .run();
    return context.json(
      discordStageInstance(channel.id, channel.guild_id, topic),
      200,
      discordRateLimitHeaders(),
    );
  },
);
app.get("/api/v10/channels/:channelId", async (context) => {
  const bot = await authenticateBot(context.env, context.req.raw);
  if (!bot) return discordError(context, 401, 0, "401: Unauthorized");
  const access = await accessibleChannel(
    context.env,
    context.req.param("channelId"),
    bot.userId,
  );
  if (!access) return discordError(context, 403, 50001, "Missing Access");
  return context.json(
    await discordChannel(context.env, access.id, bot.userId),
    200,
    discordRateLimitHeaders(),
  );
});
app.patch("/api/v10/channels/:channelId", async (context) => {
  const bot = await authenticateBot(context.env, context.req.raw);
  if (!bot) return discordError(context, 401, 0, "401: Unauthorized");
  const access = await accessibleChannel(
    context.env,
    context.req.param("channelId"),
    bot.userId,
  );
  if (!access) return discordError(context, 403, 50001, "Missing Access");
  if (
    access.guild_id.startsWith("dm:") ||
    !hasPermission(access.permissions, PermissionFlags.MANAGE_CHANNELS)
  )
    return discordError(context, 403, 50013, "Missing Permissions");
  const body = await context.req
    .json<{
      name?: string;
      topic?: string | null;
      rate_limit_per_user?: number;
      position?: number;
    }>()
    .catch(
      () =>
        ({}) as {
          name?: string;
          topic?: string | null;
          rate_limit_per_user?: number;
          position?: number;
        },
    );
  if (
    (body.name !== undefined &&
      (body.name.length < 1 || body.name.length > 100)) ||
    (body.topic !== undefined &&
      body.topic !== null &&
      body.topic.length > 4096) ||
    (body.rate_limit_per_user !== undefined &&
      (!Number.isInteger(body.rate_limit_per_user) ||
        body.rate_limit_per_user < 0 ||
        body.rate_limit_per_user > 21_600)) ||
    (body.position !== undefined && !Number.isInteger(body.position))
  )
    return discordError(context, 400, 50035, "Invalid Form Body");
  const guild = await guildDatabase(context.env, access.guild_id);
  const current = await guild.db
    .prepare(
      "SELECT name,topic,slowmode_seconds,position FROM channels WHERE id=?1",
    )
    .bind(access.id)
    .first<{
      name: string;
      topic: string | null;
      slowmode_seconds: number;
      position: number;
    }>();
  if (!current) return discordError(context, 404, 10003, "Unknown Channel");
  await guild.db
    .prepare(
      "UPDATE channels SET name=?1,topic=?2,slowmode_seconds=?3,position=?4 WHERE id=?5",
    )
    .bind(
      body.name ?? current.name,
      body.topic === undefined ? current.topic : body.topic,
      body.rate_limit_per_user ?? current.slowmode_seconds,
      body.position ?? current.position,
      access.id,
    )
    .run();
  return context.json(
    await discordChannel(context.env, access.id, bot.userId),
    200,
    discordRateLimitHeaders(),
  );
});
app.delete("/api/v10/channels/:channelId", async (context) => {
  const bot = await authenticateBot(context.env, context.req.raw);
  if (!bot) return discordError(context, 401, 0, "401: Unauthorized");
  const access = await accessibleChannel(
    context.env,
    context.req.param("channelId"),
    bot.userId,
  );
  if (!access) return discordError(context, 403, 50001, "Missing Access");
  if (
    access.guild_id.startsWith("dm:") ||
    !hasPermission(access.permissions, PermissionFlags.MANAGE_CHANNELS)
  )
    return discordError(context, 403, 50013, "Missing Permissions");
  const deleted = await discordChannel(context.env, access.id, bot.userId);
  const guild = await guildDatabase(context.env, access.guild_id);
  await guild.db
    .prepare("DELETE FROM channels WHERE id=?1")
    .bind(access.id)
    .run();
  await context.env.IDENTITY_DB.prepare(
    "DELETE FROM resource_directory WHERE resource_id=?1",
  )
    .bind(access.id)
    .run();
  return context.json(deleted, 200, discordRateLimitHeaders());
});
app.get("/api/v10/channels/:channelId/messages", async (context) => {
  const bot = await authenticateBot(context.env, context.req.raw);
  if (!bot) return discordError(context, 401, 0, "401: Unauthorized");
  const channel = await accessibleChannel(
    context.env,
    context.req.param("channelId"),
    bot.userId,
  );
  if (!channel) return discordError(context, 403, 50001, "Missing Access");
  if (!hasPermission(channel.permissions, PermissionFlags.READ_MESSAGE_HISTORY))
    return discordError(context, 403, 50013, "Missing Permissions");
  const response = await channelStub(context.env, channel.id).fetch(
    new Request(
      `https://do/messages?limit=${Math.min(Number(context.req.query("limit") ?? 50), 100)}&viewer=${encodeURIComponent(bot.userId)}`,
    ),
  );
  const payload = await response.json<{
    messages: Record<string, unknown>[];
  }>();
  return context.json(
    payload.messages.map(discordMessage),
    200,
    discordRateLimitHeaders(),
  );
});
app.get("/api/v10/channels/:channelId/messages/:messageId", async (context) => {
  const bot = await authenticateBot(context.env, context.req.raw);
  if (!bot) return discordError(context, 401, 0, "401: Unauthorized");
  const channel = await accessibleChannel(
    context.env,
    context.req.param("channelId"),
    bot.userId,
  );
  if (!channel) return discordError(context, 403, 50001, "Missing Access");
  if (!hasPermission(channel.permissions, PermissionFlags.READ_MESSAGE_HISTORY))
    return discordError(context, 403, 50013, "Missing Permissions");
  const response = await channelStub(context.env, channel.id).fetch(
    `https://do/messages/${encodeURIComponent(context.req.param("messageId"))}?viewer=${encodeURIComponent(bot.userId)}`,
  );
  if (response.status === 404)
    return discordError(context, 404, 10008, "Unknown Message");
  return context.json(
    discordMessage(await response.json<Record<string, unknown>>()),
    200,
    discordRateLimitHeaders(),
  );
});
app.post("/api/v10/channels/:channelId/messages", async (context) => {
  const bot = await authenticateBot(context.env, context.req.raw);
  if (!bot) return discordError(context, 401, 0, "401: Unauthorized");
  const channel = await accessibleChannel(
    context.env,
    context.req.param("channelId"),
    bot.userId,
  );
  if (!channel) return discordError(context, 403, 50001, "Missing Access");
  if (!hasPermission(channel.permissions, PermissionFlags.SEND_MESSAGES))
    return discordError(context, 403, 50013, "Missing Permissions");
  const body = await context.req
    .json<{
      content?: string;
      message_reference?: { message_id?: string };
      poll?: {
        question?: { text?: string };
        answers?: Array<{ poll_media?: { text?: string } }>;
        duration?: number;
        allow_multiselect?: boolean;
      };
    }>()
    .catch(
      () =>
        ({}) as {
          content?: string;
          message_reference?: { message_id?: string };
          poll?: {
            question?: { text?: string };
            answers?: Array<{ poll_media?: { text?: string } }>;
            duration?: number;
            allow_multiselect?: boolean;
          };
        },
    );
  const poll = body.poll
    ? {
        question: body.poll.question?.text ?? "",
        answers: (body.poll.answers ?? []).map(
          (answer) => answer.poll_media?.text ?? "",
        ),
        durationHours: body.poll.duration ?? 24,
        allowMultiselect: Boolean(body.poll.allow_multiselect),
      }
    : undefined;
  if (
    (!body.content && !poll) ||
    (body.content?.length ?? 0) > 4000 ||
    (poll !== undefined &&
      (!hasPermission(channel.permissions, PermissionFlags.SEND_POLLS) ||
        poll.question.length < 1 ||
        poll.question.length > 300 ||
        poll.answers.length < 2 ||
        poll.answers.length > 10 ||
        poll.answers.some(
          (answer) => answer.length < 1 || answer.length > 55,
        ) ||
        !Number.isInteger(poll.durationHours) ||
        poll.durationHours < 1 ||
        poll.durationHours > 768))
  )
    return discordError(context, 400, 50035, "Invalid Form Body");
  const id = await generateId(context.env, channel.id);
  const response = await channelStub(context.env, channel.id).fetch(
    new Request("https://do/messages", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        id,
        channelId: channel.id,
        authorId: bot.userId,
        authorUsername: bot.username,
        authorDisplayName: bot.username,
        authorBot: true,
        content: body.content ?? "",
        createdAt: nowIso(),
        replyToId: body.message_reference?.message_id ?? null,
        attachments: [],
        poll,
        partitionKey: channel.guild_id,
        slowmodeSeconds: channel.slowmode_seconds,
        bypassSlowmode: hasPermission(
          channel.permissions,
          PermissionFlags.BYPASS_SLOWMODE,
        ),
      }),
    }),
  );
  const message = await response.json<Record<string, unknown>>();
  if (!channel.guild_id.startsWith("dm:")) {
    const guild = await guildDatabase(context.env, channel.guild_id);
    await guild.db
      .prepare("UPDATE channels SET last_message_id=?1 WHERE id=?2")
      .bind(id, channel.id)
      .run();
  }
  return context.json(discordMessage(message), 200, discordRateLimitHeaders());
});
app.patch(
  "/api/v10/channels/:channelId/messages/:messageId",
  async (context) => {
    const bot = await authenticateBot(context.env, context.req.raw);
    if (!bot) return discordError(context, 401, 0, "401: Unauthorized");
    const channel = await accessibleChannel(
      context.env,
      context.req.param("channelId"),
      bot.userId,
    );
    if (!channel) return discordError(context, 403, 50001, "Missing Access");
    const body = await context.req
      .json<{ content?: string }>()
      .catch(() => ({}) as { content?: string });
    if (typeof body.content !== "string" || body.content.length > 4000)
      return discordError(context, 400, 50035, "Invalid Form Body");
    const response = await channelStub(context.env, channel.id).fetch(
      new Request(
        `https://do/messages/${encodeURIComponent(context.req.param("messageId"))}`,
        {
          method: "PATCH",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            actorId: bot.userId,
            canManage: hasPermission(
              channel.permissions,
              PermissionFlags.MANAGE_MESSAGES,
            ),
            content: body.content,
            partitionKey: channel.guild_id,
          }),
        },
      ),
    );
    if (response.status === 404)
      return discordError(context, 404, 10008, "Unknown Message");
    if (response.status === 403)
      return discordError(context, 403, 50013, "Missing Permissions");
    return context.json(
      discordMessage(await response.json<Record<string, unknown>>()),
      200,
      discordRateLimitHeaders(),
    );
  },
);
app.delete(
  "/api/v10/channels/:channelId/messages/:messageId",
  async (context) => {
    const bot = await authenticateBot(context.env, context.req.raw);
    if (!bot) return discordError(context, 401, 0, "401: Unauthorized");
    const channel = await accessibleChannel(
      context.env,
      context.req.param("channelId"),
      bot.userId,
    );
    if (!channel) return discordError(context, 403, 50001, "Missing Access");
    const response = await channelStub(context.env, channel.id).fetch(
      new Request(
        `https://do/messages/${encodeURIComponent(context.req.param("messageId"))}`,
        {
          method: "DELETE",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            actorId: bot.userId,
            canManage: hasPermission(
              channel.permissions,
              PermissionFlags.MANAGE_MESSAGES,
            ),
            partitionKey: channel.guild_id,
          }),
        },
      ),
    );
    if (response.status === 404)
      return discordError(context, 404, 10008, "Unknown Message");
    if (response.status === 403)
      return discordError(context, 403, 50013, "Missing Permissions");
    return new Response(null, {
      status: 204,
      headers: discordRateLimitHeaders(),
    });
  },
);
app.on(
  ["PUT", "DELETE"],
  "/api/v10/channels/:channelId/messages/:messageId/reactions/:emoji/@me",
  async (context) => {
    const bot = await authenticateBot(context.env, context.req.raw);
    if (!bot) return discordError(context, 401, 0, "401: Unauthorized");
    const channel = await accessibleChannel(
      context.env,
      context.req.param("channelId"),
      bot.userId,
    );
    if (!channel) return discordError(context, 403, 50001, "Missing Access");
    if (
      context.req.method === "PUT" &&
      !hasPermission(channel.permissions, PermissionFlags.ADD_REACTIONS)
    )
      return discordError(context, 403, 50013, "Missing Permissions");
    const response = await channelStub(context.env, channel.id).fetch(
      new Request(
        `https://do/messages/${encodeURIComponent(context.req.param("messageId"))}/reactions/${encodeURIComponent(context.req.param("emoji"))}`,
        {
          method: context.req.method,
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            actorId: bot.userId,
            partitionKey: channel.guild_id,
          }),
        },
      ),
    );
    if (response.status === 404)
      return discordError(context, 404, 10008, "Unknown Message");
    return new Response(null, {
      status: 204,
      headers: discordRateLimitHeaders(),
    });
  },
);
app.on(
  ["PUT", "DELETE"],
  "/api/v10/channels/:channelId/polls/:messageId/answers/:answerId/@me",
  async (context) => {
    const bot = await authenticateBot(context.env, context.req.raw);
    if (!bot) return discordError(context, 401, 0, "401: Unauthorized");
    const channel = await accessibleChannel(
      context.env,
      context.req.param("channelId"),
      bot.userId,
    );
    if (!channel) return discordError(context, 403, 50001, "Missing Access");
    const response = await channelStub(context.env, channel.id).fetch(
      new Request(
        `https://do/polls/${encodeURIComponent(context.req.param("messageId"))}/answers/${encodeURIComponent(context.req.param("answerId"))}`,
        {
          method: context.req.method,
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            actorId: bot.userId,
            partitionKey: channel.guild_id,
          }),
        },
      ),
    );
    if (response.status === 404)
      return discordError(context, 404, 10008, "Unknown Message");
    if (!response.ok)
      return discordError(context, 400, 50035, "Invalid Form Body");
    return new Response(null, {
      status: 204,
      headers: discordRateLimitHeaders(),
    });
  },
);
app.get("/api/v10/channels/:channelId/pins", async (context) => {
  const bot = await authenticateBot(context.env, context.req.raw);
  if (!bot) return discordError(context, 401, 0, "401: Unauthorized");
  const channel = await accessibleChannel(
    context.env,
    context.req.param("channelId"),
    bot.userId,
  );
  if (!channel) return discordError(context, 403, 50001, "Missing Access");
  const response = await channelStub(context.env, channel.id).fetch(
    `https://do/pins?viewer=${encodeURIComponent(bot.userId)}`,
  );
  const rows = await response.json<Record<string, unknown>[]>();
  return context.json(rows.map(discordMessage), 200, discordRateLimitHeaders());
});
app.on(
  ["PUT", "DELETE"],
  "/api/v10/channels/:channelId/pins/:messageId",
  async (context) => {
    const bot = await authenticateBot(context.env, context.req.raw);
    if (!bot) return discordError(context, 401, 0, "401: Unauthorized");
    const channel = await accessibleChannel(
      context.env,
      context.req.param("channelId"),
      bot.userId,
    );
    if (!channel) return discordError(context, 403, 50001, "Missing Access");
    if (
      !hasPermission(channel.permissions, PermissionFlags.PIN_MESSAGES) &&
      !hasPermission(channel.permissions, PermissionFlags.MANAGE_MESSAGES)
    )
      return discordError(context, 403, 50013, "Missing Permissions");
    const response = await channelStub(context.env, channel.id).fetch(
      new Request(
        `https://do/pins/${encodeURIComponent(context.req.param("messageId"))}`,
        {
          method: context.req.method,
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            canManage: true,
            partitionKey: channel.guild_id,
          }),
        },
      ),
    );
    if (response.status === 404)
      return discordError(context, 404, 10008, "Unknown Message");
    return new Response(null, {
      status: 204,
      headers: discordRateLimitHeaders(),
    });
  },
);
app.get("/api/v10/guilds/:guildId", async (context) => {
  const bot = await authenticateBot(context.env, context.req.raw);
  if (!bot) return discordError(context, 401, 0, "401: Unauthorized");
  if (!(await isMember(context.env, context.req.param("guildId"), bot.userId)))
    return discordError(context, 403, 50001, "Missing Access");
  const guild = await discordGuild(context.env, context.req.param("guildId"));
  if (!guild) return discordError(context, 404, 10004, "Unknown Guild");
  return context.json(guild, 200, discordRateLimitHeaders());
});
app.get("/api/v10/guilds/:guildId/channels", async (context) => {
  const bot = await authenticateBot(context.env, context.req.raw);
  if (!bot) return discordError(context, 401, 0, "401: Unauthorized");
  const guildId = context.req.param("guildId");
  if (!(await isMember(context.env, guildId, bot.userId)))
    return discordError(context, 403, 50001, "Missing Access");
  const routed = await guildDatabase(context.env, guildId);
  const rows = await routed.db
    .prepare("SELECT id FROM channels WHERE guild_id=?1 ORDER BY position")
    .bind(guildId)
    .all<{ id: string }>();
  const channels = (
    await Promise.all(
      rows.results.map((row) =>
        discordChannel(context.env, row.id, bot.userId),
      ),
    )
  ).filter((channel) => channel !== null);
  return context.json(channels, 200, discordRateLimitHeaders());
});
app.get("/api/v10/guilds/:guildId/scheduled-events", async (context) => {
  const bot = await authenticateBot(context.env, context.req.raw);
  if (!bot) return discordError(context, 401, 0, "401: Unauthorized");
  const guildId = context.req.param("guildId");
  if (!(await isMember(context.env, guildId, bot.userId)))
    return discordError(context, 403, 50001, "Missing Access");
  const guild = await guildDatabase(context.env, guildId);
  const rows = await guild.db
    .prepare(
      `SELECT id,guild_id,channel_id,creator_id,name,description,starts_at,ends_at,status
         FROM scheduled_events WHERE guild_id=?1 ORDER BY starts_at`,
    )
    .bind(guildId)
    .all<DiscordScheduledEventRow>();
  return context.json(
    await Promise.all(
      rows.results.map((row) => discordScheduledEvent(context.env, row)),
    ),
    200,
    discordRateLimitHeaders(),
  );
});
app.get("/api/v10/guilds/:guildId/auto-moderation/rules", async (context) => {
  const bot = await authenticateBot(context.env, context.req.raw);
  if (!bot) return discordError(context, 401, 0, "401: Unauthorized");
  const guildId = context.req.param("guildId");
  if (!(await isMember(context.env, guildId, bot.userId)))
    return discordError(context, 403, 50001, "Missing Access");
  const guild = await guildDatabase(context.env, guildId);
  const rows = await guild.db
    .prepare(
      `SELECT id,guild_id,name,trigger_metadata,action_type,enabled,creator_id
         FROM automod_rules WHERE guild_id=?1 ORDER BY created_at`,
    )
    .bind(guildId)
    .all<DiscordAutoModRow>();
  return context.json(
    rows.results.map(discordAutoModRule),
    200,
    discordRateLimitHeaders(),
  );
});
app.get(
  "/api/v10/guilds/:guildId/auto-moderation/rules/:ruleId",
  async (context) => {
    const bot = await authenticateBot(context.env, context.req.raw);
    if (!bot) return discordError(context, 401, 0, "401: Unauthorized");
    const guildId = context.req.param("guildId");
    if (!(await isMember(context.env, guildId, bot.userId)))
      return discordError(context, 403, 50001, "Missing Access");
    const guild = await guildDatabase(context.env, guildId);
    const row = await guild.db
      .prepare(
        `SELECT id,guild_id,name,trigger_metadata,action_type,enabled,creator_id
           FROM automod_rules WHERE id=?1 AND guild_id=?2`,
      )
      .bind(context.req.param("ruleId"), guildId)
      .first<DiscordAutoModRow>();
    if (!row)
      return discordError(context, 404, 10004, "Unknown Auto Moderation Rule");
    return context.json(
      discordAutoModRule(row),
      200,
      discordRateLimitHeaders(),
    );
  },
);
app.post("/api/v10/guilds/:guildId/auto-moderation/rules", async (context) => {
  const bot = await authenticateBot(context.env, context.req.raw);
  if (!bot) return discordError(context, 401, 0, "401: Unauthorized");
  const guildId = context.req.param("guildId");
  if (
    !(await hasGuildPermission(
      context.env,
      guildId,
      null,
      bot.userId,
      PermissionFlags.MANAGE_GUILD,
    ))
  )
    return discordError(context, 403, 50013, "Missing Permissions");
  const body = await context.req
    .json<{
      name?: string;
      event_type?: number;
      trigger_type?: number;
      trigger_metadata?: { keyword_filter?: string[] };
      actions?: Array<{ type?: number }>;
      enabled?: boolean;
    }>()
    .catch(() => null);
  const keywords = [
    ...new Set(
      (body?.trigger_metadata?.keyword_filter ?? [])
        .map((keyword) => keyword.trim().toLocaleLowerCase())
        .filter(Boolean),
    ),
  ].slice(0, 100);
  if (
    !body?.name ||
    body.name.length > 100 ||
    (body.event_type ?? 1) !== 1 ||
    body.trigger_type !== 1 ||
    keywords.length === 0 ||
    keywords.some((keyword) => keyword.length > 100) ||
    body.actions?.length !== 1 ||
    body.actions[0]?.type !== 1
  )
    return discordError(context, 400, 50035, "Invalid Form Body");
  const row: DiscordAutoModRow = {
    id: await generateId(context.env, guildId),
    guild_id: guildId,
    name: body.name,
    trigger_metadata: JSON.stringify({ keywords }),
    action_type: "block",
    enabled: body.enabled === false ? 0 : 1,
    creator_id: bot.userId,
  };
  const guild = await guildDatabase(context.env, guildId);
  const timestamp = nowIso();
  await guild.db
    .prepare(
      `INSERT INTO automod_rules(id,guild_id,name,trigger_type,trigger_metadata,action_type,enabled,creator_id,created_at,updated_at)
       VALUES (?1,?2,?3,'keyword',?4,'block',?5,?6,?7,?7)`,
    )
    .bind(
      row.id,
      guildId,
      row.name,
      row.trigger_metadata,
      row.enabled,
      row.creator_id,
      timestamp,
    )
    .run();
  return context.json(discordAutoModRule(row), 201, discordRateLimitHeaders());
});
app.patch(
  "/api/v10/guilds/:guildId/auto-moderation/rules/:ruleId",
  async (context) => {
    const bot = await authenticateBot(context.env, context.req.raw);
    if (!bot) return discordError(context, 401, 0, "401: Unauthorized");
    const guildId = context.req.param("guildId");
    if (
      !(await hasGuildPermission(
        context.env,
        guildId,
        null,
        bot.userId,
        PermissionFlags.MANAGE_GUILD,
      ))
    )
      return discordError(context, 403, 50013, "Missing Permissions");
    const guild = await guildDatabase(context.env, guildId);
    const current = await guild.db
      .prepare(
        `SELECT id,guild_id,name,trigger_metadata,action_type,enabled,creator_id
           FROM automod_rules WHERE id=?1 AND guild_id=?2`,
      )
      .bind(context.req.param("ruleId"), guildId)
      .first<DiscordAutoModRow>();
    if (!current)
      return discordError(context, 404, 10004, "Unknown Auto Moderation Rule");
    const body = await context.req
      .json<{
        name?: string;
        trigger_metadata?: { keyword_filter?: string[] };
        actions?: Array<{ type?: number }>;
        enabled?: boolean;
      }>()
      .catch(() => null);
    if (!body) return discordError(context, 400, 50035, "Invalid Form Body");
    const name = body.name ?? current.name;
    const oldMetadata = JSON.parse(current.trigger_metadata) as {
      keywords?: string[];
    };
    const keywords = [
      ...new Set(
        (body.trigger_metadata?.keyword_filter ?? oldMetadata.keywords ?? [])
          .map((keyword) => keyword.trim().toLocaleLowerCase())
          .filter(Boolean),
      ),
    ].slice(0, 100);
    if (
      !name ||
      name.length > 100 ||
      keywords.length === 0 ||
      keywords.some((keyword) => keyword.length > 100) ||
      (body.actions !== undefined &&
        (body.actions.length !== 1 || body.actions[0]?.type !== 1))
    )
      return discordError(context, 400, 50035, "Invalid Form Body");
    const updated: DiscordAutoModRow = {
      ...current,
      name,
      trigger_metadata: JSON.stringify({ keywords }),
      enabled:
        body.enabled === undefined ? current.enabled : body.enabled ? 1 : 0,
    };
    await guild.db
      .prepare(
        `UPDATE automod_rules
            SET name=?1,trigger_metadata=?2,enabled=?3,updated_at=?4
          WHERE id=?5 AND guild_id=?6`,
      )
      .bind(
        updated.name,
        updated.trigger_metadata,
        updated.enabled,
        nowIso(),
        updated.id,
        guildId,
      )
      .run();
    return context.json(
      discordAutoModRule(updated),
      200,
      discordRateLimitHeaders(),
    );
  },
);
app.delete(
  "/api/v10/guilds/:guildId/auto-moderation/rules/:ruleId",
  async (context) => {
    const bot = await authenticateBot(context.env, context.req.raw);
    if (!bot) return discordError(context, 401, 0, "401: Unauthorized");
    const guildId = context.req.param("guildId");
    if (
      !(await hasGuildPermission(
        context.env,
        guildId,
        null,
        bot.userId,
        PermissionFlags.MANAGE_GUILD,
      ))
    )
      return discordError(context, 403, 50013, "Missing Permissions");
    const guild = await guildDatabase(context.env, guildId);
    const result = await guild.db
      .prepare("DELETE FROM automod_rules WHERE id=?1 AND guild_id=?2")
      .bind(context.req.param("ruleId"), guildId)
      .run();
    if (result.meta.changes !== 1)
      return discordError(context, 404, 10004, "Unknown Auto Moderation Rule");
    return new Response(null, {
      status: 204,
      headers: discordRateLimitHeaders(),
    });
  },
);
app.post("/api/v10/guilds/:guildId/scheduled-events", async (context) => {
  const bot = await authenticateBot(context.env, context.req.raw);
  if (!bot) return discordError(context, 401, 0, "401: Unauthorized");
  const guildId = context.req.param("guildId");
  if (
    !(await hasGuildPermission(
      context.env,
      guildId,
      null,
      bot.userId,
      PermissionFlags.MANAGE_EVENTS,
    ))
  )
    return discordError(context, 403, 50013, "Missing Permissions");
  const body = await context.req
    .json<{
      channel_id?: string | null;
      name?: string;
      description?: string;
      scheduled_start_time?: string;
      scheduled_end_time?: string;
      entity_type?: number;
      privacy_level?: number;
    }>()
    .catch(() => null);
  if (
    !body?.name ||
    body.name.length > 100 ||
    !body.scheduled_start_time ||
    Number.isNaN(Date.parse(body.scheduled_start_time)) ||
    (body.scheduled_end_time &&
      Number.isNaN(Date.parse(body.scheduled_end_time))) ||
    ![2, 3].includes(body.entity_type ?? (body.channel_id ? 2 : 3)) ||
    (body.privacy_level !== undefined && body.privacy_level !== 2)
  )
    return discordError(context, 400, 50035, "Invalid Form Body");
  if (body.channel_id) {
    const channel = await accessibleChannel(
      context.env,
      body.channel_id,
      bot.userId,
    );
    if (
      !channel ||
      channel.guild_id !== guildId ||
      !["GUILD_VOICE", "GUILD_STAGE_VOICE"].includes(channel.type)
    )
      return discordError(context, 400, 50035, "Invalid Form Body");
  }
  const row: DiscordScheduledEventRow = {
    id: await generateId(context.env, guildId),
    guild_id: guildId,
    channel_id: body.channel_id ?? null,
    creator_id: bot.userId,
    name: body.name,
    description: body.description ?? null,
    starts_at: new Date(body.scheduled_start_time).toISOString(),
    ends_at: body.scheduled_end_time
      ? new Date(body.scheduled_end_time).toISOString()
      : null,
    status: "scheduled",
  };
  const guild = await guildDatabase(context.env, guildId);
  await guild.db
    .prepare(
      `INSERT INTO scheduled_events(id,guild_id,channel_id,creator_id,name,description,starts_at,ends_at,status,created_at)
       VALUES (?1,?2,?3,?4,?5,?6,?7,?8,'scheduled',?9)`,
    )
    .bind(
      row.id,
      row.guild_id,
      row.channel_id,
      row.creator_id,
      row.name,
      row.description,
      row.starts_at,
      row.ends_at,
      nowIso(),
    )
    .run();
  return context.json(
    await discordScheduledEvent(context.env, row),
    201,
    discordRateLimitHeaders(),
  );
});
app.get(
  "/api/v10/guilds/:guildId/scheduled-events/:eventId",
  async (context) => {
    const bot = await authenticateBot(context.env, context.req.raw);
    if (!bot) return discordError(context, 401, 0, "401: Unauthorized");
    const guildId = context.req.param("guildId");
    if (!(await isMember(context.env, guildId, bot.userId)))
      return discordError(context, 403, 50001, "Missing Access");
    const guild = await guildDatabase(context.env, guildId);
    const row = await guild.db
      .prepare(
        `SELECT id,guild_id,channel_id,creator_id,name,description,starts_at,ends_at,status
           FROM scheduled_events WHERE id=?1 AND guild_id=?2`,
      )
      .bind(context.req.param("eventId"), guildId)
      .first<DiscordScheduledEventRow>();
    if (!row)
      return discordError(context, 404, 10070, "Unknown Guild Scheduled Event");
    return context.json(
      await discordScheduledEvent(context.env, row),
      200,
      discordRateLimitHeaders(),
    );
  },
);
app.patch(
  "/api/v10/guilds/:guildId/scheduled-events/:eventId",
  async (context) => {
    const bot = await authenticateBot(context.env, context.req.raw);
    if (!bot) return discordError(context, 401, 0, "401: Unauthorized");
    const guildId = context.req.param("guildId");
    if (
      !(await hasGuildPermission(
        context.env,
        guildId,
        null,
        bot.userId,
        PermissionFlags.MANAGE_EVENTS,
      ))
    )
      return discordError(context, 403, 50013, "Missing Permissions");
    const guild = await guildDatabase(context.env, guildId);
    const current = await guild.db
      .prepare(
        `SELECT id,guild_id,channel_id,creator_id,name,description,starts_at,ends_at,status
           FROM scheduled_events WHERE id=?1 AND guild_id=?2`,
      )
      .bind(context.req.param("eventId"), guildId)
      .first<DiscordScheduledEventRow>();
    if (!current)
      return discordError(context, 404, 10070, "Unknown Guild Scheduled Event");
    const body = await context.req
      .json<{
        channel_id?: string | null;
        name?: string;
        description?: string | null;
        scheduled_start_time?: string;
        scheduled_end_time?: string | null;
        status?: number;
      }>()
      .catch(() => null);
    if (!body) return discordError(context, 400, 50035, "Invalid Form Body");
    const channelId =
      body.channel_id === undefined ? current.channel_id : body.channel_id;
    const name = body.name ?? current.name;
    const startsAt = body.scheduled_start_time
      ? new Date(body.scheduled_start_time).toISOString()
      : current.starts_at;
    const endsAt =
      body.scheduled_end_time === undefined
        ? current.ends_at
        : body.scheduled_end_time
          ? new Date(body.scheduled_end_time).toISOString()
          : null;
    const statusByCode: Record<number, string> = {
      1: "scheduled",
      2: "active",
      3: "completed",
      4: "canceled",
    };
    const status =
      body.status === undefined ? current.status : statusByCode[body.status];
    if (
      !name ||
      name.length > 100 ||
      Number.isNaN(Date.parse(startsAt)) ||
      (endsAt !== null && Number.isNaN(Date.parse(endsAt))) ||
      !status
    )
      return discordError(context, 400, 50035, "Invalid Form Body");
    if (channelId) {
      const channel = await accessibleChannel(
        context.env,
        channelId,
        bot.userId,
      );
      if (
        !channel ||
        channel.guild_id !== guildId ||
        !["GUILD_VOICE", "GUILD_STAGE_VOICE"].includes(channel.type)
      )
        return discordError(context, 400, 50035, "Invalid Form Body");
    }
    const updated: DiscordScheduledEventRow = {
      ...current,
      channel_id: channelId,
      name,
      description:
        body.description === undefined ? current.description : body.description,
      starts_at: startsAt,
      ends_at: endsAt,
      status,
    };
    await guild.db
      .prepare(
        `UPDATE scheduled_events
            SET channel_id=?1,name=?2,description=?3,starts_at=?4,ends_at=?5,status=?6
          WHERE id=?7 AND guild_id=?8`,
      )
      .bind(
        updated.channel_id,
        updated.name,
        updated.description,
        updated.starts_at,
        updated.ends_at,
        updated.status,
        updated.id,
        guildId,
      )
      .run();
    return context.json(
      await discordScheduledEvent(context.env, updated),
      200,
      discordRateLimitHeaders(),
    );
  },
);
app.delete(
  "/api/v10/guilds/:guildId/scheduled-events/:eventId",
  async (context) => {
    const bot = await authenticateBot(context.env, context.req.raw);
    if (!bot) return discordError(context, 401, 0, "401: Unauthorized");
    const guildId = context.req.param("guildId");
    if (
      !(await hasGuildPermission(
        context.env,
        guildId,
        null,
        bot.userId,
        PermissionFlags.MANAGE_EVENTS,
      ))
    )
      return discordError(context, 403, 50013, "Missing Permissions");
    const guild = await guildDatabase(context.env, guildId);
    const result = await guild.db
      .prepare("DELETE FROM scheduled_events WHERE id=?1 AND guild_id=?2")
      .bind(context.req.param("eventId"), guildId)
      .run();
    if (result.meta.changes !== 1)
      return discordError(context, 404, 10070, "Unknown Guild Scheduled Event");
    return new Response(null, {
      status: 204,
      headers: discordRateLimitHeaders(),
    });
  },
);
app.get("/api/v10/guilds/:guildId/roles", async (context) => {
  const bot = await authenticateBot(context.env, context.req.raw);
  if (!bot) return discordError(context, 401, 0, "401: Unauthorized");
  const guildId = context.req.param("guildId");
  if (!(await isMember(context.env, guildId, bot.userId)))
    return discordError(context, 403, 50001, "Missing Access");
  const guild = await guildDatabase(context.env, guildId);
  const roles = await guild.db
    .prepare(
      "SELECT id,name,permissions,position,color,managed FROM roles WHERE guild_id=?1 ORDER BY position",
    )
    .bind(guildId)
    .all<DiscordRoleRow>();
  return context.json(
    roles.results.map(discordRole),
    200,
    discordRateLimitHeaders(),
  );
});
app.post("/api/v10/guilds/:guildId/roles", async (context) => {
  const bot = await authenticateBot(context.env, context.req.raw);
  if (!bot) return discordError(context, 401, 0, "401: Unauthorized");
  const guildId = context.req.param("guildId");
  if (
    !(await hasGuildPermission(
      context.env,
      guildId,
      null,
      bot.userId,
      PermissionFlags.MANAGE_ROLES,
    ))
  )
    return discordError(context, 403, 50013, "Missing Permissions");
  const body = await context.req
    .json<{ name?: string; permissions?: string; color?: number }>()
    .catch(
      () => ({}) as { name?: string; permissions?: string; color?: number },
    );
  const permissions = parsePermissionBits(body.permissions ?? "0");
  if (
    (body.name !== undefined &&
      (body.name.length < 1 || body.name.length > 100)) ||
    permissions === null ||
    (body.color !== undefined &&
      (!Number.isInteger(body.color) ||
        body.color < 0 ||
        body.color > 0xffffff))
  )
    return discordError(context, 400, 50035, "Invalid Form Body");
  const guild = await guildDatabase(context.env, guildId);
  const position = await guild.db
    .prepare(
      "SELECT coalesce(max(position),0)+1 AS value FROM roles WHERE guild_id=?1",
    )
    .bind(guildId)
    .first<{ value: number }>();
  const role: DiscordRoleRow = {
    id: await generateId(context.env, guildId),
    name: body.name ?? "new role",
    permissions: permissions.toString(),
    position: position?.value ?? 1,
    color: body.color ?? 0,
    managed: 0,
  };
  await guild.db
    .prepare(
      `INSERT INTO roles(id,guild_id,name,permissions,position,color,managed,created_at)
       VALUES (?1,?2,?3,?4,?5,?6,0,?7)`,
    )
    .bind(
      role.id,
      guildId,
      role.name,
      role.permissions,
      role.position,
      role.color,
      nowIso(),
    )
    .run();
  return context.json(discordRole(role), 200, discordRateLimitHeaders());
});
app.patch("/api/v10/guilds/:guildId/roles/:roleId", async (context) => {
  const bot = await authenticateBot(context.env, context.req.raw);
  if (!bot) return discordError(context, 401, 0, "401: Unauthorized");
  const guildId = context.req.param("guildId");
  if (
    !(await hasGuildPermission(
      context.env,
      guildId,
      null,
      bot.userId,
      PermissionFlags.MANAGE_ROLES,
    ))
  )
    return discordError(context, 403, 50013, "Missing Permissions");
  const guild = await guildDatabase(context.env, guildId);
  const current = await guild.db
    .prepare(
      "SELECT id,name,permissions,position,color,managed FROM roles WHERE id=?1 AND guild_id=?2",
    )
    .bind(context.req.param("roleId"), guildId)
    .first<DiscordRoleRow>();
  if (!current) return discordError(context, 404, 10011, "Unknown Role");
  if (current.managed)
    return discordError(context, 403, 50013, "Missing Permissions");
  const body = await context.req
    .json<{ name?: string; permissions?: string; color?: number }>()
    .catch(
      () => ({}) as { name?: string; permissions?: string; color?: number },
    );
  const permissions =
    body.permissions === undefined
      ? BigInt(current.permissions)
      : parsePermissionBits(body.permissions);
  if (
    permissions === null ||
    (body.name !== undefined &&
      (body.name.length < 1 || body.name.length > 100)) ||
    (body.color !== undefined &&
      (!Number.isInteger(body.color) ||
        body.color < 0 ||
        body.color > 0xffffff))
  )
    return discordError(context, 400, 50035, "Invalid Form Body");
  const role = {
    ...current,
    name: body.name ?? current.name,
    permissions: permissions.toString(),
    color: body.color ?? current.color,
  };
  await guild.db
    .prepare("UPDATE roles SET name=?1,permissions=?2,color=?3 WHERE id=?4")
    .bind(role.name, role.permissions, role.color, role.id)
    .run();
  return context.json(discordRole(role), 200, discordRateLimitHeaders());
});
app.delete("/api/v10/guilds/:guildId/roles/:roleId", async (context) => {
  const bot = await authenticateBot(context.env, context.req.raw);
  if (!bot) return discordError(context, 401, 0, "401: Unauthorized");
  const guildId = context.req.param("guildId");
  if (
    context.req.param("roleId") === guildId ||
    !(await hasGuildPermission(
      context.env,
      guildId,
      null,
      bot.userId,
      PermissionFlags.MANAGE_ROLES,
    ))
  )
    return discordError(context, 403, 50013, "Missing Permissions");
  const guild = await guildDatabase(context.env, guildId);
  const result = await guild.db
    .prepare("DELETE FROM roles WHERE id=?1 AND guild_id=?2 AND managed=0")
    .bind(context.req.param("roleId"), guildId)
    .run();
  if (result.meta.changes !== 1)
    return discordError(context, 404, 10011, "Unknown Role");
  return new Response(null, {
    status: 204,
    headers: discordRateLimitHeaders(),
  });
});
app.get("/api/v10/guilds/:guildId/members", async (context) => {
  const bot = await authenticateBot(context.env, context.req.raw);
  if (!bot) return discordError(context, 401, 0, "401: Unauthorized");
  const guildId = context.req.param("guildId");
  if (!(await isMember(context.env, guildId, bot.userId)))
    return discordError(context, 403, 50001, "Missing Access");
  const limit = Math.min(
    Math.max(Number(context.req.query("limit") ?? 1000), 1),
    1000,
  );
  const guild = await guildDatabase(context.env, guildId);
  const members = await guild.db
    .prepare(
      "SELECT user_id,nickname,role_ids,timeout_until,joined_at FROM members WHERE guild_id=?1 AND user_id>?2 ORDER BY user_id LIMIT ?3",
    )
    .bind(guildId, context.req.query("after") ?? "", limit)
    .all<DiscordMemberRow>();
  return context.json(
    await Promise.all(
      members.results.map((member) => discordMember(context.env, member)),
    ),
    200,
    discordRateLimitHeaders(),
  );
});
app.get("/api/v10/guilds/:guildId/members/:userId", async (context) => {
  const bot = await authenticateBot(context.env, context.req.raw);
  if (!bot) return discordError(context, 401, 0, "401: Unauthorized");
  const guildId = context.req.param("guildId");
  if (!(await isMember(context.env, guildId, bot.userId)))
    return discordError(context, 403, 50001, "Missing Access");
  const guild = await guildDatabase(context.env, guildId);
  const member = await guild.db
    .prepare(
      "SELECT user_id,nickname,role_ids,timeout_until,joined_at FROM members WHERE guild_id=?1 AND user_id=?2",
    )
    .bind(guildId, context.req.param("userId"))
    .first<DiscordMemberRow>();
  if (!member) return discordError(context, 404, 10007, "Unknown Member");
  return context.json(
    await discordMember(context.env, member),
    200,
    discordRateLimitHeaders(),
  );
});
app.on(
  ["PUT", "DELETE"],
  "/api/v10/guilds/:guildId/members/:userId/roles/:roleId",
  async (context) => {
    const bot = await authenticateBot(context.env, context.req.raw);
    if (!bot) return discordError(context, 401, 0, "401: Unauthorized");
    const guildId = context.req.param("guildId");
    if (
      !(await hasGuildPermission(
        context.env,
        guildId,
        null,
        bot.userId,
        PermissionFlags.MANAGE_ROLES,
      ))
    )
      return discordError(context, 403, 50013, "Missing Permissions");
    const guild = await guildDatabase(context.env, guildId);
    const member = await guild.db
      .prepare("SELECT role_ids FROM members WHERE guild_id=?1 AND user_id=?2")
      .bind(guildId, context.req.param("userId"))
      .first<{ role_ids: string }>();
    const role = await guild.db
      .prepare("SELECT 1 FROM roles WHERE guild_id=?1 AND id=?2")
      .bind(guildId, context.req.param("roleId"))
      .first();
    if (!member) return discordError(context, 404, 10007, "Unknown Member");
    if (!role) return discordError(context, 404, 10011, "Unknown Role");
    const roles = new Set(JSON.parse(member.role_ids) as string[]);
    if (context.req.method === "PUT") roles.add(context.req.param("roleId"));
    else if (context.req.param("roleId") !== guildId)
      roles.delete(context.req.param("roleId"));
    roles.add(guildId);
    await guild.db
      .prepare(
        "UPDATE members SET role_ids=?1 WHERE guild_id=?2 AND user_id=?3",
      )
      .bind(JSON.stringify([...roles]), guildId, context.req.param("userId"))
      .run();
    return new Response(null, {
      status: 204,
      headers: discordRateLimitHeaders(),
    });
  },
);
app.get("/api/v10/guilds/:guildId/bans", async (context) => {
  const bot = await authenticateBot(context.env, context.req.raw);
  if (!bot) return discordError(context, 401, 0, "401: Unauthorized");
  const guildId = context.req.param("guildId");
  if (
    !(await hasGuildPermission(
      context.env,
      guildId,
      null,
      bot.userId,
      PermissionFlags.BAN_MEMBERS,
    ))
  )
    return discordError(context, 403, 50013, "Missing Permissions");
  const guild = await guildDatabase(context.env, guildId);
  const bans = await guild.db
    .prepare(
      "SELECT user_id,reason FROM bans WHERE guild_id=?1 ORDER BY created_at DESC LIMIT 1000",
    )
    .bind(guildId)
    .all<{ user_id: string; reason: string }>();
  return context.json(
    await Promise.all(
      bans.results.map(async (ban) => ({
        reason: ban.reason,
        user: await discordUser(context.env, ban.user_id),
      })),
    ),
    200,
    discordRateLimitHeaders(),
  );
});
app.on(
  ["PUT", "DELETE"],
  "/api/v10/guilds/:guildId/bans/:userId",
  async (context) => {
    const bot = await authenticateBot(context.env, context.req.raw);
    if (!bot) return discordError(context, 401, 0, "401: Unauthorized");
    const guildId = context.req.param("guildId");
    if (
      !(await hasGuildPermission(
        context.env,
        guildId,
        null,
        bot.userId,
        PermissionFlags.BAN_MEMBERS,
      ))
    )
      return discordError(context, 403, 50013, "Missing Permissions");
    const guild = await guildDatabase(context.env, guildId);
    if (context.req.method === "DELETE") {
      await guild.db
        .prepare("DELETE FROM bans WHERE guild_id=?1 AND user_id=?2")
        .bind(guildId, context.req.param("userId"))
        .run();
      return new Response(null, {
        status: 204,
        headers: discordRateLimitHeaders(),
      });
    }
    if (
      !(await canModerateMember(
        context.env,
        guildId,
        bot.userId,
        context.req.param("userId"),
      ))
    )
      return discordError(context, 403, 50013, "Missing Permissions");
    const reason = (context.req.header("x-audit-log-reason") ?? "").slice(
      0,
      512,
    );
    await guild.db.batch([
      guild.db
        .prepare("DELETE FROM members WHERE guild_id=?1 AND user_id=?2")
        .bind(guildId, context.req.param("userId")),
      guild.db
        .prepare(
          `INSERT INTO bans(guild_id,user_id,moderator_id,reason,created_at)
           VALUES (?1,?2,?3,?4,?5)
           ON CONFLICT(guild_id,user_id) DO UPDATE SET moderator_id=excluded.moderator_id,
             reason=excluded.reason,created_at=excluded.created_at`,
        )
        .bind(
          guildId,
          context.req.param("userId"),
          bot.userId,
          reason,
          nowIso(),
        ),
    ]);
    await context.env.IDENTITY_DB.prepare(
      "DELETE FROM bot_guild_installs WHERE guild_id=?1 AND bot_user_id=?2",
    )
      .bind(guildId, context.req.param("userId"))
      .run();
    await removeGuildMembershipIndex(
      context.env,
      context.req.param("userId"),
      guildId,
    );
    return new Response(null, {
      status: 204,
      headers: discordRateLimitHeaders(),
    });
  },
);
app.get("/api/v10/channels/:channelId/webhooks", async (context) => {
  const bot = await authenticateBot(context.env, context.req.raw);
  if (!bot) return discordError(context, 401, 0, "401: Unauthorized");
  const channel = await accessibleChannel(
    context.env,
    context.req.param("channelId"),
    bot.userId,
  );
  if (!channel) return discordError(context, 403, 50001, "Missing Access");
  if (!hasPermission(channel.permissions, PermissionFlags.MANAGE_WEBHOOKS))
    return discordError(context, 403, 50013, "Missing Permissions");
  const rows = await context.env.IDENTITY_DB.prepare(
    `SELECT id,application_id,guild_id,channel_id,creator_id,name,avatar_key
       FROM webhooks WHERE channel_id=?1 ORDER BY created_at`,
  )
    .bind(channel.id)
    .all<DiscordWebhookRow>();
  return context.json(
    await Promise.all(
      rows.results.map((row) => discordWebhook(context.env, row)),
    ),
    200,
    discordRateLimitHeaders(),
  );
});
app.post("/api/v10/channels/:channelId/webhooks", async (context) => {
  const bot = await authenticateBot(context.env, context.req.raw);
  if (!bot) return discordError(context, 401, 0, "401: Unauthorized");
  const channel = await accessibleChannel(
    context.env,
    context.req.param("channelId"),
    bot.userId,
  );
  if (!channel) return discordError(context, 403, 50001, "Missing Access");
  if (
    channel.guild_id.startsWith("dm:") ||
    !hasPermission(channel.permissions, PermissionFlags.MANAGE_WEBHOOKS)
  )
    return discordError(context, 403, 50013, "Missing Permissions");
  const body = await context.req
    .json<{ name?: string; avatar?: string | null }>()
    .catch(() => ({}) as { name?: string; avatar?: string | null });
  if (
    !body.name ||
    body.name.length < 1 ||
    body.name.length > 80 ||
    body.avatar
  )
    return discordError(context, 400, 50035, "Invalid Form Body");
  const id = await generateId(context.env, channel.id);
  const token = randomToken(48);
  const row: DiscordWebhookRow = {
    id,
    application_id: bot.applicationId,
    guild_id: channel.guild_id,
    channel_id: channel.id,
    creator_id: bot.userId,
    name: body.name,
    avatar_key: null,
  };
  await context.env.IDENTITY_DB.prepare(
    `INSERT INTO webhooks(
       id,application_id,guild_id,channel_id,creator_id,name,avatar_key,
       token_hash,token_ciphertext,created_at
     ) VALUES (?1,?2,?3,?4,?5,?6,NULL,?7,?8,?9)`,
  )
    .bind(
      id,
      bot.applicationId,
      channel.guild_id,
      channel.id,
      bot.userId,
      body.name,
      await sha256(token),
      await encryptString(
        token,
        await getSecret(context.env, "DATA_ENCRYPTION_KEY"),
      ),
      nowIso(),
    )
    .run();
  return context.json(
    { ...(await discordWebhook(context.env, row)), token },
    200,
    discordRateLimitHeaders(),
  );
});
app.get("/api/v10/webhooks/:webhookId/:token", async (context) => {
  const webhook = await authenticateWebhook(
    context.env,
    context.req.param("webhookId"),
    context.req.param("token"),
  );
  if (!webhook) return discordError(context, 404, 10015, "Unknown Webhook");
  return context.json(
    {
      ...(await discordWebhook(context.env, webhook)),
      token: context.req.param("token"),
    },
    200,
    discordRateLimitHeaders(),
  );
});
app.patch("/api/v10/webhooks/:webhookId/:token", async (context) => {
  const webhook = await authenticateWebhook(
    context.env,
    context.req.param("webhookId"),
    context.req.param("token"),
  );
  if (!webhook) return discordError(context, 404, 10015, "Unknown Webhook");
  const body = await context.req
    .json<{ name?: string }>()
    .catch(() => ({}) as { name?: string });
  if (
    body.name !== undefined &&
    (body.name.length < 1 || body.name.length > 80)
  )
    return discordError(context, 400, 50035, "Invalid Form Body");
  webhook.name = body.name ?? webhook.name;
  await context.env.IDENTITY_DB.prepare(
    "UPDATE webhooks SET name=?1 WHERE id=?2",
  )
    .bind(webhook.name, webhook.id)
    .run();
  return context.json(
    {
      ...(await discordWebhook(context.env, webhook)),
      token: context.req.param("token"),
    },
    200,
    discordRateLimitHeaders(),
  );
});
app.delete("/api/v10/webhooks/:webhookId/:token", async (context) => {
  const webhook = await authenticateWebhook(
    context.env,
    context.req.param("webhookId"),
    context.req.param("token"),
  );
  if (!webhook) return discordError(context, 404, 10015, "Unknown Webhook");
  await context.env.IDENTITY_DB.prepare("DELETE FROM webhooks WHERE id=?1")
    .bind(webhook.id)
    .run();
  return new Response(null, {
    status: 204,
    headers: discordRateLimitHeaders(),
  });
});
app.post(
  "/api/v10/interactions/:interactionId/:token/callback",
  async (context) => {
    const body = await context.req
      .json<{ type?: number; data?: Record<string, unknown> }>()
      .catch(() => null);
    if (!body?.type || ![4, 5, 6, 7, 8, 9].includes(body.type))
      return discordError(context, 400, 50035, "Invalid Form Body");
    const interaction = await context.env.IDENTITY_DB.prepare(
      `SELECT id,application_id,bot_user_id,guild_id,channel_id,state,expires_at
         FROM interaction_tokens
        WHERE id=?1 AND token_hash=?2`,
    )
      .bind(
        context.req.param("interactionId"),
        await sha256(context.req.param("token")),
      )
      .first<{
        id: string;
        application_id: string;
        bot_user_id: string;
        guild_id: string | null;
        channel_id: string;
        state: string;
        expires_at: string;
      }>();
    if (!interaction || Date.parse(interaction.expires_at) <= Date.now())
      return discordError(context, 404, 10062, "Unknown Interaction");
    if (interaction.state !== "pending")
      return discordError(
        context,
        400,
        40060,
        "Interaction has already been acknowledged",
      );
    const claimed = await context.env.IDENTITY_DB.prepare(
      "UPDATE interaction_tokens SET state='processing' WHERE id=?1 AND state='pending'",
    )
      .bind(interaction.id)
      .run();
    if (claimed.meta.changes !== 1)
      return discordError(
        context,
        400,
        40060,
        "Interaction has already been acknowledged",
      );
    let responseData: Record<string, unknown> = body.data ?? {};
    if (body.type === 4 && (Number(body.data?.flags ?? 0) & 64) === 0) {
      const content = String(body.data?.content ?? "");
      if (content.length > 4000) {
        await context.env.IDENTITY_DB.prepare(
          "UPDATE interaction_tokens SET state='pending' WHERE id=?1",
        )
          .bind(interaction.id)
          .run();
        return discordError(context, 400, 50035, "Invalid Form Body");
      }
      const bot = await context.env.IDENTITY_DB.prepare(
        "SELECT username,display_name FROM users WHERE id=?1",
      )
        .bind(interaction.bot_user_id)
        .first<{ username: string; display_name: string }>();
      const channel = await accessibleChannel(
        context.env,
        interaction.channel_id,
        interaction.bot_user_id,
      );
      if (!bot || !channel) {
        await context.env.IDENTITY_DB.prepare(
          "UPDATE interaction_tokens SET state='pending' WHERE id=?1",
        )
          .bind(interaction.id)
          .run();
        return discordError(context, 403, 50001, "Missing Access");
      }
      const messageId = await generateId(context.env, channel.id);
      const response = await channelStub(context.env, channel.id).fetch(
        new Request("https://do/messages", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            id: messageId,
            channelId: channel.id,
            authorId: interaction.bot_user_id,
            authorUsername: bot.username,
            authorDisplayName: bot.display_name,
            authorBot: true,
            content,
            createdAt: nowIso(),
            replyToId: null,
            attachments: [],
            partitionKey: channel.guild_id,
            slowmodeSeconds: channel.slowmode_seconds,
            bypassSlowmode: true,
          }),
        }),
      );
      if (!response.ok) {
        await context.env.IDENTITY_DB.prepare(
          "UPDATE interaction_tokens SET state='pending' WHERE id=?1",
        )
          .bind(interaction.id)
          .run();
        return discordError(context, 400, 50035, "Invalid Form Body");
      }
      responseData = {
        ...body.data,
        message: discordMessage(await response.json<Record<string, unknown>>()),
      };
    } else if (body.type === 4) {
      const content = String(body.data?.content ?? "");
      if (content.length > 4000) {
        await context.env.IDENTITY_DB.prepare(
          "UPDATE interaction_tokens SET state='pending' WHERE id=?1",
        )
          .bind(interaction.id)
          .run();
        return discordError(context, 400, 50035, "Invalid Form Body");
      }
      responseData = {
        ...body.data,
        message: await ephemeralInteractionMessage(
          context.env,
          await generateId(context.env, interaction.channel_id),
          interaction.channel_id,
          interaction.bot_user_id,
          content,
        ),
      };
    }
    const state = [5, 6].includes(body.type) ? "deferred" : "responded";
    await context.env.IDENTITY_DB.prepare(
      `UPDATE interaction_tokens SET state=?1,response_type=?2,response_json=?3,
         responded_at=?4 WHERE id=?5`,
    )
      .bind(
        state,
        body.type,
        JSON.stringify(responseData),
        nowIso(),
        interaction.id,
      )
      .run();
    return new Response(null, {
      status: 204,
      headers: discordRateLimitHeaders(),
    });
  },
);
app.on(
  ["GET", "PATCH", "DELETE"],
  "/api/v10/webhooks/:applicationId/:token/messages/@original",
  (context) => handleInteractionWebhookMessage(context, null),
);
app.on(
  ["GET", "PATCH", "DELETE"],
  "/api/v10/webhooks/:applicationId/:token/messages/:messageId",
  (context) =>
    handleInteractionWebhookMessage(context, context.req.param("messageId")),
);
app.post("/api/v10/webhooks/:webhookId/:token", async (context) => {
  const interaction = await authenticateInteractionWebhook(
    context.env,
    context.req.param("webhookId"),
    context.req.param("token"),
  );
  if (interaction) {
    const body = await context.req
      .json<{ content?: string; flags?: number }>()
      .catch(() => null);
    if (!body || typeof body.content !== "string" || body.content.length > 4000)
      return discordError(context, 400, 50035, "Invalid Form Body");
    if ((Number(body.flags ?? 0) & 64) !== 0)
      return context.json(
        await ephemeralInteractionMessage(
          context.env,
          await generateId(context.env, interaction.channel_id),
          interaction.channel_id,
          interaction.bot_user_id,
          body.content,
        ),
        200,
        discordRateLimitHeaders(),
      );
    const message = await createInteractionWebhookMessage(
      context.env,
      interaction,
      body.content,
    );
    if (!message) return discordError(context, 403, 50001, "Missing Access");
    if (interaction.state === "deferred") {
      await context.env.IDENTITY_DB.prepare(
        `UPDATE interaction_tokens
            SET state='responded',response_type=4,response_json=?1,responded_at=?2
          WHERE id=?3`,
      )
        .bind(JSON.stringify({ ...body, message }), nowIso(), interaction.id)
        .run();
    }
    return context.json(message, 200, discordRateLimitHeaders());
  }
  const webhook = await authenticateWebhook(
    context.env,
    context.req.param("webhookId"),
    context.req.param("token"),
  );
  if (!webhook) return discordError(context, 404, 10015, "Unknown Webhook");
  const channel = await accessibleChannel(
    context.env,
    webhook.channel_id,
    webhook.creator_id,
  );
  if (!channel) return discordError(context, 403, 50001, "Missing Access");
  if (!hasPermission(channel.permissions, PermissionFlags.SEND_MESSAGES))
    return discordError(context, 403, 50013, "Missing Permissions");
  const body = await context.req
    .json<{ content?: string; username?: string; avatar_url?: string }>()
    .catch(
      () =>
        ({}) as { content?: string; username?: string; avatar_url?: string },
    );
  if (
    !body.content ||
    body.content.length > 4000 ||
    (body.username !== undefined &&
      (body.username.length < 1 || body.username.length > 80)) ||
    body.avatar_url
  )
    return discordError(context, 400, 50035, "Invalid Form Body");
  const id = await generateId(context.env, channel.id);
  const response = await channelStub(context.env, channel.id).fetch(
    new Request("https://do/messages", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        id,
        channelId: channel.id,
        authorId: webhook.id,
        authorUsername: body.username ?? webhook.name,
        authorDisplayName: body.username ?? webhook.name,
        authorBot: true,
        content: body.content,
        createdAt: nowIso(),
        replyToId: null,
        attachments: [],
        partitionKey: channel.guild_id,
        slowmodeSeconds: channel.slowmode_seconds,
        bypassSlowmode: true,
      }),
    }),
  );
  if (!response.ok)
    return discordError(context, 400, 50035, "Invalid Form Body");
  if (context.req.query("wait") === "true")
    return context.json(
      {
        ...discordMessage(await response.json<Record<string, unknown>>()),
        webhook_id: webhook.id,
      },
      200,
      discordRateLimitHeaders(),
    );
  return new Response(null, {
    status: 204,
    headers: discordRateLimitHeaders(),
  });
});
app.on(
  ["GET", "POST", "PUT"],
  "/api/v10/applications/:applicationId/commands",
  (context) => handleDiscordCommands(context, null),
);
app.on(
  ["GET", "PATCH", "DELETE"],
  "/api/v10/applications/:applicationId/commands/:commandId",
  (context) => handleDiscordCommand(context, null),
);
app.on(
  ["GET", "POST", "PUT"],
  "/api/v10/applications/:applicationId/guilds/:guildId/commands",
  (context) => handleDiscordCommands(context, context.req.param("guildId")),
);
app.on(
  ["GET", "PATCH", "DELETE"],
  "/api/v10/applications/:applicationId/guilds/:guildId/commands/:commandId",
  (context) => handleDiscordCommand(context, context.req.param("guildId")),
);
app.get("/api/v10/compatibility", (context) =>
  context.json({
    snapshot: "2026-08-10",
    apiVersion: 10,
    status: "partial",
    implementedGroups: [
      "Gateway JSON identify/resume/heartbeat and core message/interaction dispatch",
      "Channel and message CRUD, reactions, pins and polls",
      "Guild, role, member, ban, scheduled-event and AutoMod resources",
      "Forum/thread creation and membership, and Stage instance lifecycle",
      "Application commands, interaction responses and follow-ups",
      "Webhooks",
      "Cloudflare Realtime voice adapter endpoints",
    ],
    pending: [
      "ETF and zlib-stream Gateway transports",
      "remaining Discord v10 routes, events and object fields",
      "OAuth2 authorization flow parity",
      "Discord UDP/RTP voice wire compatibility",
    ],
    adapters: ["discord.js@14.27.0", "discord.py@2.7.1", "JDA@6.4.2"],
    voice: "cloudflare-realtime-adapter-required",
  }),
);

app.notFound(async (context) => {
  if (context.req.path.startsWith("/api/") || context.req.path === "/health")
    return apiError(context, 404, "NOT_FOUND", "Route not found");
  return context.env.ASSETS.fetch(context.req.raw);
});
app.onError((error, context) => {
  if (error instanceof ShardCutoverError) {
    context.header("retry-after", "15");
    return apiError(
      context,
      503,
      "SHARD_CUTOVER",
      "This shard is completing a migration; retry the write shortly",
      {
        domain: error.resolution.domain,
        bucket: error.resolution.bucket,
        generation: error.resolution.generation,
      },
    );
  }
  console.error(
    JSON.stringify({
      traceId: context.get("traceId"),
      error: error.message,
      stack: error.stack,
    }),
  );
  return apiError(context, 500, "INTERNAL_ERROR", "An internal error occurred");
});

async function generateId(env: Env, key: string): Promise<string> {
  const worker = snowflakeShardFor(key, 1024);
  const stub = env.ID_GENERATORS.get(
    env.ID_GENERATORS.idFromName(`worker-${worker}`),
  );
  const response = await stub.fetch(`https://id/generate?worker=${worker}`, {
    method: "POST",
  });
  if (!response.ok) throw new Error("ID generator unavailable");
  return (await response.json<{ id: string }>()).id;
}

interface RateLimitResult {
  allowed: boolean;
  limit: number;
  remaining: number;
  resetAt: number;
  retryAfterMs: number;
}

async function consumeRateLimit(
  env: Env,
  subject: string,
  scope: string,
  limit: number,
  windowMs: number,
): Promise<RateLimitResult> {
  const stub = env.USER_SESSIONS.get(
    env.USER_SESSIONS.idFromName(`rate:${subject}`),
  );
  const response = await stub.fetch("https://session.internal/rate-limit", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ scope, limit, windowMs }),
  });
  if (!response.ok) throw new Error("Rate limiter rejected its input");
  return response.json<RateLimitResult>();
}

function applyRateLimitHeaders(
  context: Context<Application>,
  result: RateLimitResult,
) {
  context.header("x-ratelimit-limit", String(result.limit));
  context.header("x-ratelimit-remaining", String(result.remaining));
  context.header("x-ratelimit-reset", String(Math.ceil(result.resetAt / 1000)));
  if (!result.allowed)
    context.header(
      "retry-after",
      String(Math.ceil(result.retryAfterMs / 1000)),
    );
}

async function pkceChallenge(verifier: string): Promise<string> {
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)),
  );
  let binary = "";
  for (const byte of digest) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
}

async function makeAccessToken(
  env: Env,
  userId: string,
  sessionId: string,
  username: string,
  displayName: string,
): Promise<string> {
  const signingKey = await getSecret(env, "JWT_SIGNING_KEY");
  return signAccessToken(
    { sub: userId, sid: sessionId, kind: "user", username, displayName },
    signingKey,
    `${Number(env.ACCESS_TOKEN_TTL_SECONDS)}s`,
  );
}

async function createSession(
  env: Env,
  request: Request,
  user: { id: string; username: string; display_name: string },
) {
  const sessionId = crypto.randomUUID();
  const familyId = crypto.randomUUID();
  const refreshToken = randomToken(48);
  const timestamp = nowIso();
  await env.IDENTITY_DB.prepare(
    "INSERT INTO sessions(id, user_id, family_id, refresh_hash, user_agent, ip_hmac, expires_at, created_at, last_seen_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)",
  )
    .bind(
      sessionId,
      user.id,
      familyId,
      await sha256(refreshToken),
      request.headers.get("user-agent"),
      await clientIpHmac(env, request),
      new Date(
        Date.now() + Number(env.REFRESH_TOKEN_TTL_SECONDS) * 1000,
      ).toISOString(),
      timestamp,
    )
    .run();
  return {
    accessToken: await makeAccessToken(
      env,
      user.id,
      sessionId,
      user.username,
      user.display_name,
    ),
    refreshToken,
    expiresIn: Number(env.ACCESS_TOKEN_TTL_SECONDS),
  };
}

async function isMember(
  env: Env,
  guildId: string,
  userId: string,
): Promise<boolean> {
  const guild = await guildDatabase(env, guildId);
  return Boolean(
    await firstWithDualRead(guild, (db) =>
      db
        .prepare(
          "SELECT 1 AS present FROM members WHERE guild_id=?1 AND user_id=?2",
        )
        .bind(guildId, userId),
    ),
  );
}

async function isGuildOwner(
  env: Env,
  guildId: string,
  userId: string,
): Promise<boolean> {
  const guild = await guildDatabase(env, guildId);
  return Boolean(
    await firstWithDualRead(guild, (db) =>
      db
        .prepare("SELECT 1 AS present FROM guilds WHERE id=?1 AND owner_id=?2")
        .bind(guildId, userId),
    ),
  );
}

async function isAdmin(env: Env, userId: string): Promise<boolean> {
  return Boolean(
    await env.IDENTITY_DB.prepare(
      "SELECT 1 AS present FROM instance_admins WHERE user_id=?1",
    )
      .bind(userId)
      .first(),
  );
}

async function configNumber(
  env: Env,
  key: string,
  fallback: number,
): Promise<number> {
  const row = await env.IDENTITY_DB.prepare(
    "SELECT value FROM instance_config WHERE key=?1",
  )
    .bind(key)
    .first<{ value: string }>();
  const value = Number(row?.value ?? fallback);
  return Number.isFinite(value) && value >= 0 ? value : fallback;
}

interface ChannelAccess {
  id: string;
  guild_id: string;
  type: string;
  slowmode_seconds: number;
  timeout_until: string | null;
  permissions: bigint;
}

interface DiscordRealtimeTracks {
  sessionDescription?: { sdp?: string; type?: string };
  tracks: Array<{
    location?: "local" | "remote";
    mid?: string | null;
    trackName?: string;
    sessionId?: string;
    kind?: "audio" | "video";
    label?: "microphone" | "camera" | "screen";
    simulcast?: {
      preferredRid?: string;
      priorityOrdering?: "none" | "asciibetical";
      ridNotAvailable?: "none" | "asciibetical";
    };
  }>;
}

async function createDiscordVoiceSession(
  env: Env,
  channelId: string,
  userId: string,
): Promise<Response> {
  const realtimeToken = await getOptionalSecret(env, "REALTIME_API_TOKEN");
  if (!env.REALTIME_APP_ID || !realtimeToken)
    return Response.json(
      { code: 0, message: "Cloudflare Realtime is not configured" },
      { status: 503 },
    );
  const response = await fetch(
    `https://rtc.live.cloudflare.com/v1/apps/${env.REALTIME_APP_ID}/sessions/new`,
    {
      method: "POST",
      headers: {
        authorization: `Bearer ${realtimeToken}`,
        "content-type": "application/json",
      },
      body: "{}",
    },
  );
  const text = await response.text();
  if (!response.ok)
    return new Response(text, {
      status: response.status,
      headers: { "content-type": "application/json" },
    });
  const session = JSON.parse(text) as { sessionId?: string };
  if (!session.sessionId)
    return Response.json(
      { code: 0, message: "Cloudflare Realtime session was invalid" },
      { status: 502 },
    );
  const registered = await voiceStub(env, channelId).fetch(
    "https://do/session",
    {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ userId, sessionId: session.sessionId }),
    },
  );
  if (!registered.ok)
    return Response.json(
      { code: 50013, message: "Join the voice channel first" },
      { status: 409 },
    );
  return Response.json(session);
}

async function updateDiscordVoiceTracks(
  env: Env,
  channel: ChannelAccess,
  userId: string,
  sessionId: string,
  body: DiscordRealtimeTracks,
): Promise<Response> {
  const realtimeToken = await getOptionalSecret(env, "REALTIME_API_TOKEN");
  if (!env.REALTIME_APP_ID || !realtimeToken)
    return Response.json(
      { code: 0, message: "Cloudflare Realtime is not configured" },
      { status: 503 },
    );
  if (!(await ownsRealtimeSession(env, channel.id, userId, sessionId)))
    return Response.json(
      { code: 50013, message: "Realtime session does not belong to this bot" },
      { status: 403 },
    );
  const response = await fetch(
    `https://rtc.live.cloudflare.com/v1/apps/${env.REALTIME_APP_ID}/sessions/${sessionId}/tracks/new`,
    {
      method: "POST",
      headers: {
        authorization: `Bearer ${realtimeToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        sessionDescription: body.sessionDescription,
        tracks: body.tracks.map((track) => ({
          location: track.location,
          mid: track.mid,
          trackName: track.trackName,
          sessionId: track.sessionId,
          simulcast: track.simulcast,
        })),
      }),
    },
  );
  const responseText = await response.text();
  if (response.ok) {
    const published = body.tracks
      .filter(
        (track) =>
          track.location === "local" &&
          track.trackName &&
          track.kind &&
          track.label,
      )
      .map((track) => ({
        trackName: track.trackName!,
        kind: track.kind!,
        label: track.label!,
      }));
    if (published.length > 0)
      await voiceStub(env, channel.id).fetch("https://do/tracks", {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ userId, sessionId, tracks: published }),
      });
  }
  return new Response(responseText, {
    status: response.status,
    headers: { "content-type": "application/json" },
  });
}

async function renegotiateDiscordVoiceSession(
  env: Env,
  channelId: string,
  userId: string,
  sessionId: string,
  sessionDescription: { sdp?: string; type?: string },
): Promise<Response> {
  const realtimeToken = await getOptionalSecret(env, "REALTIME_API_TOKEN");
  if (!env.REALTIME_APP_ID || !realtimeToken)
    return Response.json(
      { code: 0, message: "Cloudflare Realtime is not configured" },
      { status: 503 },
    );
  if (!(await ownsRealtimeSession(env, channelId, userId, sessionId)))
    return Response.json(
      { code: 50013, message: "Realtime session does not belong to this bot" },
      { status: 403 },
    );
  const response = await fetch(
    `https://rtc.live.cloudflare.com/v1/apps/${env.REALTIME_APP_ID}/sessions/${sessionId}/renegotiate`,
    {
      method: "PUT",
      headers: {
        authorization: `Bearer ${realtimeToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ sessionDescription }),
    },
  );
  return new Response(response.body, {
    status: response.status,
    headers: { "content-type": "application/json" },
  });
}

async function closeDiscordVoiceTracks(
  env: Env,
  channelId: string,
  userId: string,
  sessionId: string,
  body: { trackNames?: string[]; mids?: string[] },
): Promise<Response> {
  if (!(await ownsRealtimeSession(env, channelId, userId, sessionId)))
    return Response.json(
      { code: 50013, message: "Realtime session does not belong to this bot" },
      { status: 403 },
    );
  if (body.mids?.length) {
    const realtimeToken = await getOptionalSecret(env, "REALTIME_API_TOKEN");
    if (!env.REALTIME_APP_ID || !realtimeToken)
      return Response.json(
        { code: 0, message: "Cloudflare Realtime is not configured" },
        { status: 503 },
      );
    const closed = await fetch(
      `https://rtc.live.cloudflare.com/v1/apps/${env.REALTIME_APP_ID}/sessions/${sessionId}/tracks/close`,
      {
        method: "PUT",
        headers: {
          authorization: `Bearer ${realtimeToken}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          tracks: body.mids.map((mid) => ({ mid })),
          force: true,
        }),
      },
    );
    if (!closed.ok)
      return new Response(closed.body, {
        status: closed.status,
        headers: { "content-type": "application/json" },
      });
  }
  if (body.trackNames?.length) {
    const removed = await voiceStub(env, channelId).fetch("https://do/tracks", {
      method: "DELETE",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ userId, sessionId, trackNames: body.trackNames }),
    });
    if (!removed.ok)
      return Response.json(
        {
          code: 50013,
          message: "Realtime session does not belong to this bot",
        },
        { status: 403 },
      );
  }
  return new Response(null, { status: 204 });
}

async function accessibleChannel(
  env: Env,
  channelId: string,
  userId: string,
): Promise<ChannelAccess | null> {
  const routed = await channelDatabase(env, channelId);
  if (!routed) return null;
  if (routed.kind === "guild") {
    const guildChannel = await firstWithDualRead<
      Omit<ChannelAccess, "permissions">
    >(routed, (db) =>
      db
        .prepare(
          "SELECT c.id,c.guild_id,c.type,c.slowmode_seconds,m.timeout_until FROM channels c JOIN members m ON m.guild_id=c.guild_id WHERE c.id=?1 AND m.user_id=?2",
        )
        .bind(channelId, userId),
    );
    if (!guildChannel) return null;
    const permissions = await calculateGuildPermissions(
      env,
      guildChannel.guild_id,
      channelId,
      userId,
    );
    if (!hasPermission(permissions, PermissionFlags.VIEW_CHANNEL)) return null;
    return { ...guildChannel, permissions };
  }
  const dm = await firstWithDualRead<Omit<ChannelAccess, "permissions">>(
    routed,
    (db) =>
      db
        .prepare(
          "SELECT c.channel_id AS id,'dm:' || c.id AS guild_id,CASE WHEN c.kind='dm' THEN 'DM' ELSE 'GROUP_DM' END AS type,0 AS slowmode_seconds,NULL AS timeout_until FROM conversations c JOIN conversation_members m ON m.conversation_id=c.id WHERE c.channel_id=?1 AND m.user_id=?2",
        )
        .bind(channelId, userId),
  );
  return dm
    ? {
        ...dm,
        permissions:
          PermissionFlags.VIEW_CHANNEL |
          PermissionFlags.SEND_MESSAGES |
          PermissionFlags.READ_MESSAGE_HISTORY,
      }
    : null;
}

async function calculateGuildPermissions(
  env: Env,
  guildId: string,
  channelId: string | null,
  userId: string,
): Promise<bigint> {
  const routed = await guildDatabase(env, guildId);
  const guild = await firstWithDualRead<{ owner_id: string }>(routed, (db) =>
    db.prepare("SELECT owner_id FROM guilds WHERE id=?1").bind(guildId),
  );
  const member = await firstWithDualRead<{ role_ids: string }>(routed, (db) =>
    db
      .prepare("SELECT role_ids FROM members WHERE guild_id=?1 AND user_id=?2")
      .bind(guildId, userId),
  );
  if (!guild || !member) return 0n;
  const roles = await routed.db
    .prepare("SELECT id,position,permissions FROM roles WHERE guild_id=?1")
    .bind(guildId)
    .all<{ id: string; position: number; permissions: string }>();
  const overwrites = channelId
    ? await routed.db
        .prepare(
          "SELECT target_id AS id,target_type AS type,allow_bits AS allow,deny_bits AS deny FROM permission_overwrites WHERE channel_id=?1",
        )
        .bind(channelId)
        .all<{
          id: string;
          type: "role" | "member";
          allow: string;
          deny: string;
        }>()
    : { results: [] };
  return calculatePermissions({
    guildOwnerId: guild.owner_id,
    memberId: userId,
    everyoneRoleId: guildId,
    roles: roles.results,
    memberRoleIds: JSON.parse(member.role_ids) as string[],
    overwrites: overwrites.results,
  });
}

async function hasGuildPermission(
  env: Env,
  guildId: string,
  channelId: string | null,
  userId: string,
  permission: bigint,
): Promise<boolean> {
  return hasPermission(
    await calculateGuildPermissions(env, guildId, channelId, userId),
    permission,
  );
}

async function canModerateMember(
  env: Env,
  guildId: string,
  actorId: string,
  targetId: string,
): Promise<boolean> {
  if (actorId === targetId) return false;
  const routed = await guildDatabase(env, guildId);
  const guild = await routed.db
    .prepare("SELECT owner_id FROM guilds WHERE id=?1")
    .bind(guildId)
    .first<{ owner_id: string }>();
  if (!guild || targetId === guild.owner_id) return false;
  if (actorId === guild.owner_id) return true;
  const members = await routed.db
    .prepare(
      "SELECT user_id,role_ids FROM members WHERE guild_id=?1 AND user_id IN (?2,?3)",
    )
    .bind(guildId, actorId, targetId)
    .all<{ user_id: string; role_ids: string }>();
  const actor = members.results.find((member) => member.user_id === actorId);
  const target = members.results.find((member) => member.user_id === targetId);
  if (!actor) return false;
  if (!target) return true;
  const roles = await routed.db
    .prepare("SELECT id,position FROM roles WHERE guild_id=?1")
    .bind(guildId)
    .all<{ id: string; position: number }>();
  const top = (roleIds: string) => {
    const ids = JSON.parse(roleIds) as string[];
    return Math.max(
      0,
      ...roles.results
        .filter((role) => ids.includes(role.id))
        .map((role) => role.position),
    );
  };
  return top(actor.role_ids) > top(target.role_ids);
}

async function appendGuildAudit(
  env: Env,
  guildId: string,
  actorId: string,
  action: string,
  targetId: string | null,
  reason: string | null = null,
  changes: unknown[] = [],
): Promise<void> {
  const routed = await guildDatabase(env, guildId);
  await routed.db
    .prepare(
      `INSERT INTO guild_audit(id,guild_id,actor_id,action,target_id,reason,changes,created_at)
       VALUES (?1,?2,?3,?4,?5,?6,?7,?8)`,
    )
    .bind(
      await generateId(env, `${guildId}:${action}`),
      guildId,
      actorId,
      action,
      targetId,
      reason,
      JSON.stringify(changes),
      nowIso(),
    )
    .run();
}

async function removeGuildMembershipIndex(
  env: Env,
  userId: string,
  guildId: string,
): Promise<void> {
  const social = await socialDatabase(env, userId);
  await social.db
    .prepare(
      "DELETE FROM guild_membership_index WHERE user_id=?1 AND guild_id=?2",
    )
    .bind(userId, guildId)
    .run();
}

async function refreshDirectoryMemberCount(
  env: Env,
  guildId: string,
  db: D1Database,
): Promise<void> {
  const count = await db
    .prepare("SELECT count(*) AS count FROM members WHERE guild_id=?1")
    .bind(guildId)
    .first<{ count: number }>();
  await env.IDENTITY_DB.prepare(
    "UPDATE guild_directory SET member_count=?1,updated_at=?2 WHERE guild_id=?3",
  )
    .bind(count?.count ?? 0, nowIso(), guildId)
    .run();
}

async function evaluateAutoMod(
  env: Env,
  guildId: string,
  content: string,
): Promise<{ id: string; action: "block" | "flag" } | null> {
  const routed = await guildDatabase(env, guildId);
  const rules = await routed.db
    .prepare(
      `SELECT id,trigger_metadata,action_type FROM automod_rules
        WHERE guild_id=?1 AND enabled=1 AND trigger_type='keyword'`,
    )
    .bind(guildId)
    .all<{
      id: string;
      trigger_metadata: string;
      action_type: "block" | "flag";
    }>();
  const normalized = content.toLocaleLowerCase();
  for (const rule of rules.results) {
    const metadata = JSON.parse(rule.trigger_metadata) as {
      keywords?: string[];
    };
    if (metadata.keywords?.some((keyword) => normalized.includes(keyword)))
      return { id: rule.id, action: rule.action_type };
  }
  return null;
}

function channelStub(env: Env, channelId: string): DurableObjectStub {
  return env.CHANNEL_HUBS.get(env.CHANNEL_HUBS.idFromName(channelId));
}

function voiceStub(env: Env, channelId: string): DurableObjectStub {
  return env.VOICE_ROOMS.get(env.VOICE_ROOMS.idFromName(channelId));
}

async function ownsRealtimeSession(
  env: Env,
  channelId: string,
  userId: string,
  sessionId: string,
): Promise<boolean> {
  const url = new URL("https://do/session");
  url.searchParams.set("user", userId);
  url.searchParams.set("session", sessionId);
  const result = await voiceStub(env, channelId).fetch(url);
  if (!result.ok) return false;
  return Boolean((await result.json<{ present?: boolean }>()).present);
}

async function failLifecycleStart(
  env: Env,
  jobId: string,
  cause: unknown,
): Promise<void> {
  await env.IDENTITY_DB.prepare(
    `UPDATE account_lifecycle_jobs
        SET phase='errored',error=?1,updated_at=?2 WHERE id=?3`,
  )
    .bind(
      cause instanceof Error ? cause.message.slice(0, 2048) : String(cause),
      nowIso(),
      jobId,
    )
    .run();
}

async function verifyAccountDeletionPasskey(
  env: Env,
  userId: string,
  response: AuthenticationResponseJSON,
): Promise<boolean> {
  const passkey = await env.IDENTITY_DB.prepare(
    `SELECT id,public_key,counter,transports FROM passkeys
      WHERE credential_id=?1 AND user_id=?2`,
  )
    .bind(response.id, userId)
    .first<{
      id: string;
      public_key: ArrayBuffer;
      counter: number;
      transports: string;
    }>();
  if (!passkey) return false;
  try {
    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge: async (challenge) =>
        consumeChallenge(env, "account_delete_passkey", challenge, userId),
      expectedOrigin: env.PUBLIC_ORIGIN,
      expectedRPID: env.RP_ID,
      requireUserVerification: true,
      credential: {
        id: response.id,
        publicKey: new Uint8Array(passkey.public_key),
        counter: passkey.counter,
        transports: JSON.parse(passkey.transports),
      },
    });
    if (!verification.verified) return false;
    await env.IDENTITY_DB.prepare(
      "UPDATE passkeys SET counter=?1,last_used_at=?2 WHERE id=?3",
    )
      .bind(verification.authenticationInfo.newCounter, nowIso(), passkey.id)
      .run();
    return true;
  } catch {
    return false;
  }
}

async function findOwnedGuild(
  env: Env,
  userId: string,
): Promise<string | null> {
  const social = await socialDatabase(env, userId);
  const memberships = await social.db
    .prepare("SELECT guild_id FROM guild_membership_index WHERE user_id=?1")
    .bind(userId)
    .all<{ guild_id: string }>();
  for (const membership of memberships.results) {
    const guild = await guildDatabase(env, membership.guild_id);
    const owned = await guild.db
      .prepare("SELECT id FROM guilds WHERE id=?1 AND owner_id=?2")
      .bind(membership.guild_id, userId)
      .first<{ id: string }>();
    if (owned) return owned.id;
  }
  return null;
}

async function consumeChallenge(
  env: Env,
  kind: string,
  challenge: string,
  userId?: string,
): Promise<boolean> {
  const challengeHash = await sha256(challenge);
  const record = await env.IDENTITY_DB.prepare(
    `SELECT id FROM auth_challenges
      WHERE kind=?1 AND challenge_hash=?2 AND consumed_at IS NULL AND expires_at>?3
        AND (?4 IS NULL OR user_id=?4)
      ORDER BY expires_at DESC LIMIT 1`,
  )
    .bind(kind, challengeHash, nowIso(), userId ?? null)
    .first<{ id: string }>();
  if (!record) return false;
  const result = await env.IDENTITY_DB.prepare(
    "UPDATE auth_challenges SET consumed_at=?1 WHERE id=?2 AND consumed_at IS NULL",
  )
    .bind(nowIso(), record.id)
    .run();
  return result.meta.changes === 1;
}

async function processQueue(
  batch: MessageBatch<QueueEvent>,
  env: Env,
): Promise<void> {
  for (const message of batch.messages) {
    try {
      const event = message.body;
      const receipt = await env.IDENTITY_DB.prepare(
        "SELECT 1 AS processed FROM queue_receipts WHERE event_id=?1",
      )
        .bind(event.id)
        .first();
      if (receipt) {
        message.ack();
        continue;
      }
      if (event.topic === "search.index") {
        const payload = event.payload as {
          messageId: string;
          channelId: string;
          content: string;
          authorName: string;
          month?: string;
        };
        const partition = payload.month ?? new Date().toISOString().slice(0, 7);
        const stub = env.SEARCH_PARTITIONS.get(
          env.SEARCH_PARTITIONS.idFromName(
            `${event.partitionKey}:${partition}`,
          ),
        );
        await stub.fetch("https://search/index", {
          method: "PUT",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(payload),
        });
      } else if (event.topic === "message.archive") {
        const payload = event.payload.message as {
          id: string;
          channelId: string;
          sequence: string;
          createdAt: string;
        };
        const month = payload.createdAt.slice(0, 7);
        const stub = env.MESSAGE_PARTITIONS.get(
          env.MESSAGE_PARTITIONS.idFromName(`${event.partitionKey}:${month}`),
        );
        await stub.fetch("https://archive/message", {
          method: "PUT",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            id: payload.id,
            channelId: payload.channelId,
            sequence: payload.sequence,
            payload,
            createdAt: payload.createdAt,
          }),
        });
      } else if (event.topic === "search.delete") {
        const payload = event.payload as { messageId: string; month?: string };
        const partition = payload.month ?? new Date().toISOString().slice(0, 7);
        const stub = env.SEARCH_PARTITIONS.get(
          env.SEARCH_PARTITIONS.idFromName(
            `${event.partitionKey}:${partition}`,
          ),
        );
        await stub.fetch(
          `https://search/index?messageId=${encodeURIComponent(payload.messageId)}`,
          { method: "DELETE" },
        );
      } else if (event.topic === "bot.dispatch") {
        const payload = event.payload as {
          event: string;
          data: Record<string, unknown>;
          guildId?: string | null;
          requiredIntent: string;
        };
        if (!payload.guildId) {
          // Bot DMs are not installed through a guild and have no dispatch target.
        } else {
          const installs = await env.IDENTITY_DB.prepare(
            "SELECT bot_user_id FROM bot_guild_installs WHERE guild_id=?1",
          )
            .bind(payload.guildId)
            .all<{ bot_user_id: string }>();
          if (installs.results.length > 0) {
            let data: Record<string, unknown> = payload.data;
            if (
              ["MESSAGE_CREATE", "MESSAGE_UPDATE"].includes(payload.event) &&
              payload.data.author
            )
              data = {
                ...discordMessage(payload.data),
                guild_id: payload.guildId,
              };
            else if (payload.event === "MESSAGE_DELETE")
              data = {
                id: payload.data.id,
                channel_id: payload.data.channelId,
                guild_id: payload.guildId,
              };
            const dispatch = await env.BOT_GATEWAY_SHARDS.get(
              env.BOT_GATEWAY_SHARDS.idFromName("0"),
            ).fetch("https://gateway/dispatch", {
              method: "POST",
              headers: { "content-type": "application/json" },
              body: JSON.stringify({
                event: payload.event,
                data,
                guildId: payload.guildId,
                requiredIntent: payload.requiredIntent,
                targetBotIds: installs.results.map(
                  (install) => install.bot_user_id,
                ),
              }),
            });
            if (!dispatch.ok) throw new Error("Bot Gateway dispatch failed");
          }
        }
      } else if (event.topic === "email") {
        const payload = event.payload as {
          template: string;
          encryptedRecipient: string;
          token: string;
        };
        const { decryptString } = await import("./crypto");
        const recipient = await decryptString(
          payload.encryptedRecipient,
          await getSecret(env, "DATA_ENCRYPTION_KEY"),
        );
        if (!["verify-email", "account-recovery"].includes(payload.template))
          throw new Error(`Unknown email template: ${payload.template}`);
        const recovery = payload.template === "account-recovery";
        const verificationUrl = `${env.PUBLIC_ORIGIN}/${recovery ? "recover" : "verify-email"}?token=${encodeURIComponent(payload.token)}`;
        await env.EMAIL.send({
          to: recipient,
          from: env.EMAIL_FROM,
          subject: `${env.APP_NAME} ${recovery ? "account recovery" : "email verification"}`,
          text: `${recovery ? "Recover your account" : "Verify your email"} within 15 minutes: ${verificationUrl}`,
          html: `<h1>${recovery ? "Recover your account" : "Verify your email"}</h1><p>This link is valid for 15 minutes and can be used once.</p><p><a href="${escapeHtml(verificationUrl)}">Continue</a></p>`,
        });
      } else if (event.topic === "voice.usage") {
        const payload = event.payload as {
          channelId: string;
          userId: string;
          sessionId: string | null;
          startedAt: string;
          endedAt: string;
          durationSeconds: number;
          audioTrackSeconds: number;
          cameraTrackSeconds: number;
          screenTrackSeconds: number;
          estimatedSourceBytes: number;
        };
        await env.IDENTITY_DB.prepare(
          `INSERT OR IGNORE INTO voice_usage(
             id,channel_id,user_id,session_id,started_at,ended_at,duration_seconds,
             audio_track_seconds,camera_track_seconds,screen_track_seconds,
             estimated_source_bytes
           ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)`,
        )
          .bind(
            event.id,
            payload.channelId,
            payload.userId,
            payload.sessionId,
            payload.startedAt,
            payload.endedAt,
            payload.durationSeconds,
            payload.audioTrackSeconds,
            payload.cameraTrackSeconds,
            payload.screenTrackSeconds,
            payload.estimatedSourceBytes,
          )
          .run();
      } else if (event.topic === "object.delete") {
        const key = event.payload.key;
        if (typeof key !== "string") throw new Error("Object key is required");
        await env.MEDIA.delete(key);
      } else {
        throw new Error(`Unsupported queue topic: ${event.topic}`);
      }
      await env.IDENTITY_DB.prepare(
        "INSERT OR IGNORE INTO queue_receipts(event_id,topic,processed_at) VALUES (?1,?2,?3)",
      )
        .bind(event.id, event.topic, nowIso())
        .run();
      message.ack();
    } catch (error) {
      console.error(
        JSON.stringify({
          topic: "queue-error",
          eventId: message.body.id,
          error: String(error),
        }),
      );
      message.retry();
    }
  }
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll('"', "&quot;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

async function authenticateBot(
  env: Env,
  request: Request,
): Promise<{
  applicationId: string;
  userId: string;
  username: string;
  intents: string;
} | null> {
  const authorization = request.headers.get("authorization");
  if (!authorization?.startsWith("Bot ")) return null;
  const row = await env.IDENTITY_DB.prepare(
    `SELECT b.application_id,b.user_id,u.username,b.intents
       FROM bots b JOIN users u ON u.id=b.user_id
      WHERE b.token_hash=?1 AND b.enabled=1`,
  )
    .bind(await sha256(authorization.slice(4)))
    .first<{
      application_id: string;
      user_id: string;
      username: string;
      intents: string;
    }>();
  return row
    ? {
        applicationId: row.application_id,
        userId: row.user_id,
        username: row.username,
        intents: row.intents,
      }
    : null;
}

interface DiscordRoleRow {
  id: string;
  name: string;
  permissions: string;
  position: number;
  color: number;
  managed: number;
}

interface DiscordMemberRow {
  user_id: string;
  nickname: string | null;
  role_ids: string;
  timeout_until: string | null;
  joined_at: string;
}

interface DiscordScheduledEventRow {
  id: string;
  guild_id: string;
  channel_id: string | null;
  creator_id: string;
  name: string;
  description: string | null;
  starts_at: string;
  ends_at: string | null;
  status: string;
}

interface DiscordAutoModRow {
  id: string;
  guild_id: string;
  name: string;
  trigger_metadata: string;
  action_type: string;
  enabled: number;
  creator_id: string;
}

interface DiscordWebhookRow {
  id: string;
  application_id: string | null;
  guild_id: string | null;
  channel_id: string;
  creator_id: string;
  name: string;
  avatar_key: string | null;
}

function discordRole(role: DiscordRoleRow) {
  return {
    id: role.id,
    name: role.name,
    description: null,
    color: role.color,
    colors: {
      primary_color: role.color,
      secondary_color: null,
      tertiary_color: null,
    },
    hoist: false,
    icon: null,
    unicode_emoji: null,
    position: role.position,
    permissions: role.permissions,
    managed: Boolean(role.managed),
    mentionable: false,
    flags: 0,
  };
}

async function discordUser(env: Env, userId: string) {
  const user = await env.IDENTITY_DB.prepare(
    `SELECT u.id,u.username,u.display_name,u.avatar_key,
            EXISTS(SELECT 1 FROM bots b WHERE b.user_id=u.id) AS is_bot
       FROM users u WHERE u.id=?1`,
  )
    .bind(userId)
    .first<{
      id: string;
      username: string;
      display_name: string;
      avatar_key: string | null;
      is_bot: number;
    }>();
  return user
    ? {
        id: user.id,
        username: user.username,
        global_name: user.display_name,
        discriminator: "0000",
        avatar: user.avatar_key,
        bot: Boolean(user.is_bot),
        system: false,
        public_flags: 0,
        flags: 0,
      }
    : {
        id: userId,
        username: "deleted-user",
        global_name: "Deleted User",
        discriminator: "0000",
        avatar: null,
        bot: false,
        system: false,
        public_flags: 0,
        flags: 0,
      };
}

async function discordMember(env: Env, member: DiscordMemberRow) {
  return {
    user: await discordUser(env, member.user_id),
    nick: member.nickname,
    avatar: null,
    banner: null,
    roles: JSON.parse(member.role_ids) as string[],
    joined_at: member.joined_at,
    premium_since: null,
    deaf: false,
    mute: false,
    flags: 0,
    pending: false,
    communication_disabled_until: member.timeout_until,
  };
}

async function interactionMember(env: Env, guildId: string, userId: string) {
  const guild = await guildDatabase(env, guildId);
  const member = await guild.db
    .prepare(
      "SELECT user_id,nickname,role_ids,timeout_until,joined_at FROM members WHERE guild_id=?1 AND user_id=?2",
    )
    .bind(guildId, userId)
    .first<DiscordMemberRow>();
  return member ? discordMember(env, member) : null;
}

async function discordScheduledEvent(env: Env, row: DiscordScheduledEventRow) {
  let entityType = 3;
  if (row.channel_id) {
    const guild = await guildDatabase(env, row.guild_id);
    const channel = await guild.db
      .prepare("SELECT type FROM channels WHERE id=?1")
      .bind(row.channel_id)
      .first<{ type: string }>();
    entityType = channel?.type === "GUILD_STAGE_VOICE" ? 1 : 2;
  }
  const statuses: Record<string, number> = {
    scheduled: 1,
    active: 2,
    completed: 3,
    canceled: 4,
  };
  return {
    id: row.id,
    guild_id: row.guild_id,
    channel_id: row.channel_id,
    creator_id: row.creator_id,
    creator: await discordUser(env, row.creator_id),
    name: row.name,
    description: row.description,
    scheduled_start_time: row.starts_at,
    scheduled_end_time: row.ends_at,
    privacy_level: 2,
    status: statuses[row.status] ?? 1,
    entity_type: entityType,
    entity_id: null,
    entity_metadata: entityType === 3 ? { location: "External" } : null,
    user_count: 0,
  };
}

function discordAutoModRule(row: DiscordAutoModRow) {
  const metadata = JSON.parse(row.trigger_metadata) as { keywords?: string[] };
  return {
    id: row.id,
    guild_id: row.guild_id,
    name: row.name,
    creator_id: row.creator_id,
    event_type: 1,
    trigger_type: 1,
    trigger_metadata: {
      keyword_filter: metadata.keywords ?? [],
      regex_patterns: [],
      presets: [],
      allow_list: [],
      mention_total_limit: 0,
      mention_raid_protection_enabled: false,
    },
    actions: [{ type: row.action_type === "block" ? 1 : 2, metadata: {} }],
    enabled: Boolean(row.enabled),
    exempt_roles: [],
    exempt_channels: [],
  };
}

function discordStageInstance(
  channelId: string,
  guildId: string,
  topic: string,
) {
  return {
    id: channelId,
    guild_id: guildId,
    channel_id: channelId,
    topic,
    privacy_level: 2,
    discoverable_disabled: true,
    guild_scheduled_event_id: null,
  };
}

async function discordGuild(env: Env, guildId: string) {
  const guild = await guildDatabase(env, guildId);
  const row = await guild.db
    .prepare(
      "SELECT id,owner_id,name,description,icon_key,features FROM guilds WHERE id=?1",
    )
    .bind(guildId)
    .first<{
      id: string;
      owner_id: string;
      name: string;
      description: string | null;
      icon_key: string | null;
      features: string;
    }>();
  if (!row) return null;
  const roles = await guild.db
    .prepare(
      "SELECT id,name,permissions,position,color,managed FROM roles WHERE guild_id=?1 ORDER BY position",
    )
    .bind(guildId)
    .all<DiscordRoleRow>();
  const emojis = await guild.db
    .prepare("SELECT id,name FROM guild_emojis WHERE guild_id=?1")
    .bind(guildId)
    .all<{ id: string; name: string }>();
  return {
    id: row.id,
    name: row.name,
    icon: row.icon_key,
    icon_hash: null,
    splash: null,
    discovery_splash: null,
    owner_id: row.owner_id,
    afk_channel_id: null,
    afk_timeout: 300,
    widget_enabled: false,
    verification_level: 0,
    default_message_notifications: 0,
    explicit_content_filter: 0,
    roles: roles.results.map(discordRole),
    emojis: emojis.results.map((emoji) => ({
      id: emoji.id,
      name: emoji.name,
      roles: [],
      require_colons: true,
      managed: false,
      animated: false,
      available: true,
    })),
    features: JSON.parse(row.features) as string[],
    mfa_level: 1,
    application_id: null,
    system_channel_id: null,
    system_channel_flags: 0,
    rules_channel_id: null,
    max_presences: null,
    max_members: 100000,
    vanity_url_code: null,
    description: row.description,
    banner: null,
    premium_tier: 0,
    premium_subscription_count: 0,
    preferred_locale: "ja",
    public_updates_channel_id: null,
    nsfw_level: 0,
    stickers: [],
    premium_progress_bar_enabled: false,
    safety_alerts_channel_id: null,
  };
}

interface InteractionWebhookRow {
  id: string;
  application_id: string;
  bot_user_id: string;
  channel_id: string;
  state: string;
  response_json: string | null;
  expires_at: string;
}

async function authenticateInteractionWebhook(
  env: Env,
  applicationId: string,
  token: string,
): Promise<InteractionWebhookRow | null> {
  if (!applicationId || !token) return null;
  const row = await env.IDENTITY_DB.prepare(
    `SELECT id,application_id,bot_user_id,channel_id,state,response_json,expires_at
       FROM interaction_tokens
      WHERE application_id=?1 AND token_hash=?2`,
  )
    .bind(applicationId, await sha256(token))
    .first<InteractionWebhookRow>();
  return row && Date.parse(row.expires_at) > Date.now() ? row : null;
}

async function createInteractionWebhookMessage(
  env: Env,
  interaction: InteractionWebhookRow,
  content: string,
): Promise<Record<string, unknown> | null> {
  const channel = await accessibleChannel(
    env,
    interaction.channel_id,
    interaction.bot_user_id,
  );
  const bot = await env.IDENTITY_DB.prepare(
    "SELECT username,display_name FROM users WHERE id=?1",
  )
    .bind(interaction.bot_user_id)
    .first<{ username: string; display_name: string }>();
  if (!channel || !bot) return null;
  const messageId = await generateId(env, channel.id);
  const response = await channelStub(env, channel.id).fetch(
    new Request("https://do/messages", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        id: messageId,
        channelId: channel.id,
        authorId: interaction.bot_user_id,
        authorUsername: bot.username,
        authorDisplayName: bot.display_name,
        authorBot: true,
        content,
        createdAt: nowIso(),
        replyToId: null,
        attachments: [],
        partitionKey: channel.guild_id,
        slowmodeSeconds: channel.slowmode_seconds,
        bypassSlowmode: true,
      }),
    }),
  );
  return response.ok
    ? discordMessage(await response.json<Record<string, unknown>>())
    : null;
}

async function ephemeralInteractionMessage(
  env: Env,
  id: string,
  channelId: string,
  botUserId: string,
  content: string,
) {
  return {
    id,
    channel_id: channelId,
    author: await discordUser(env, botUserId),
    content,
    timestamp: nowIso(),
    edited_timestamp: null,
    tts: false,
    mention_everyone: false,
    mentions: [],
    mention_roles: [],
    attachments: [],
    embeds: [],
    pinned: false,
    type: 0,
    flags: 64,
  };
}

async function handleInteractionWebhookMessage(
  context: Context<Application>,
  requestedMessageId: string | null,
) {
  const interaction = await authenticateInteractionWebhook(
    context.env,
    context.req.param("applicationId") ?? "",
    context.req.param("token") ?? "",
  );
  if (!interaction) return discordError(context, 404, 10015, "Unknown Webhook");
  const responseData = interaction.response_json
    ? (JSON.parse(interaction.response_json) as Record<string, unknown>)
    : null;
  const originalMessage = responseData?.message as
    Record<string, unknown> | undefined;
  const messageId = requestedMessageId ?? String(originalMessage?.id ?? "");
  if (!messageId) return discordError(context, 404, 10008, "Unknown Message");

  if (!requestedMessageId && Number(originalMessage?.flags ?? 0) === 64) {
    if (context.req.method === "GET")
      return context.json(originalMessage, 200, discordRateLimitHeaders());
    if (context.req.method === "DELETE") {
      await context.env.IDENTITY_DB.prepare(
        "UPDATE interaction_tokens SET response_json=NULL WHERE id=?1",
      )
        .bind(interaction.id)
        .run();
      return new Response(null, {
        status: 204,
        headers: discordRateLimitHeaders(),
      });
    }
    const body = await context.req
      .json<{ content?: string }>()
      .catch(() => null);
    if (!body || typeof body.content !== "string" || body.content.length > 4000)
      return discordError(context, 400, 50035, "Invalid Form Body");
    const updated = { ...originalMessage, content: body.content };
    await context.env.IDENTITY_DB.prepare(
      "UPDATE interaction_tokens SET response_json=?1 WHERE id=?2",
    )
      .bind(
        JSON.stringify({ ...responseData, message: updated }),
        interaction.id,
      )
      .run();
    return context.json(updated, 200, discordRateLimitHeaders());
  }

  const channel = await accessibleChannel(
    context.env,
    interaction.channel_id,
    interaction.bot_user_id,
  );
  if (!channel) return discordError(context, 403, 50001, "Missing Access");
  if (context.req.method === "GET") {
    const response = await channelStub(context.env, channel.id).fetch(
      `https://do/messages/${encodeURIComponent(messageId)}?viewer=${encodeURIComponent(interaction.bot_user_id)}`,
    );
    if (!response.ok)
      return discordError(context, 404, 10008, "Unknown Message");
    const message = await response.json<Record<string, unknown>>();
    if (
      (message.author as { id?: string } | undefined)?.id !==
      interaction.bot_user_id
    )
      return discordError(context, 404, 10008, "Unknown Message");
    return context.json(
      discordMessage(message),
      200,
      discordRateLimitHeaders(),
    );
  }
  const currentResponse = await channelStub(context.env, channel.id).fetch(
    `https://do/messages/${encodeURIComponent(messageId)}?viewer=${encodeURIComponent(interaction.bot_user_id)}`,
  );
  if (!currentResponse.ok)
    return discordError(context, 404, 10008, "Unknown Message");
  const current = await currentResponse.json<Record<string, unknown>>();
  if (
    (current.author as { id?: string } | undefined)?.id !==
    interaction.bot_user_id
  )
    return discordError(context, 404, 10008, "Unknown Message");
  if (context.req.method === "DELETE") {
    const deleted = await channelStub(context.env, channel.id).fetch(
      new Request(`https://do/messages/${encodeURIComponent(messageId)}`, {
        method: "DELETE",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          actorId: interaction.bot_user_id,
          canManage: false,
          partitionKey: channel.guild_id,
        }),
      }),
    );
    if (!deleted.ok)
      return discordError(context, 404, 10008, "Unknown Message");
    if (!requestedMessageId)
      await context.env.IDENTITY_DB.prepare(
        "UPDATE interaction_tokens SET response_json=NULL WHERE id=?1",
      )
        .bind(interaction.id)
        .run();
    return new Response(null, {
      status: 204,
      headers: discordRateLimitHeaders(),
    });
  }
  const body = await context.req.json<{ content?: string }>().catch(() => null);
  if (!body || typeof body.content !== "string" || body.content.length > 4000)
    return discordError(context, 400, 50035, "Invalid Form Body");
  const updatedResponse = await channelStub(context.env, channel.id).fetch(
    new Request(`https://do/messages/${encodeURIComponent(messageId)}`, {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        actorId: interaction.bot_user_id,
        canManage: false,
        content: body.content,
        partitionKey: channel.guild_id,
      }),
    }),
  );
  if (!updatedResponse.ok)
    return discordError(context, 404, 10008, "Unknown Message");
  const updated = discordMessage(
    await updatedResponse.json<Record<string, unknown>>(),
  );
  if (!requestedMessageId)
    await context.env.IDENTITY_DB.prepare(
      "UPDATE interaction_tokens SET response_json=?1 WHERE id=?2",
    )
      .bind(
        JSON.stringify({ ...responseData, message: updated }),
        interaction.id,
      )
      .run();
  return context.json(updated, 200, discordRateLimitHeaders());
}

async function authenticateWebhook(
  env: Env,
  webhookId: string,
  token: string,
): Promise<DiscordWebhookRow | null> {
  if (!webhookId || !token) return null;
  return env.IDENTITY_DB.prepare(
    `SELECT id,application_id,guild_id,channel_id,creator_id,name,avatar_key
       FROM webhooks WHERE id=?1 AND token_hash=?2`,
  )
    .bind(webhookId, await sha256(token))
    .first<DiscordWebhookRow>();
}

async function discordWebhook(env: Env, webhook: DiscordWebhookRow) {
  return {
    id: webhook.id,
    type: 1,
    guild_id: webhook.guild_id,
    channel_id: webhook.channel_id,
    user: await discordUser(env, webhook.creator_id),
    name: webhook.name,
    avatar: webhook.avatar_key,
    application_id: webhook.application_id,
  };
}

type DiscordCommandInput = {
  type?: number;
  name?: string;
  description?: string;
  options?: unknown[];
  default_member_permissions?: string | null;
  dm_permission?: boolean;
  nsfw?: boolean;
  name_localizations?: Record<string, string> | null;
  description_localizations?: Record<string, string> | null;
};

async function handleDiscordCommands(
  context: Context<Application>,
  guildId: string | null,
) {
  const bot = await authenticateBot(context.env, context.req.raw);
  if (!bot) return discordError(context, 401, 0, "401: Unauthorized");
  const applicationId = context.req.param("applicationId");
  if (applicationId !== bot.applicationId)
    return discordError(context, 403, 50001, "Missing Access");
  if (
    guildId &&
    !(await context.env.IDENTITY_DB.prepare(
      "SELECT 1 FROM bot_guild_installs WHERE application_id=?1 AND guild_id=?2",
    )
      .bind(applicationId, guildId)
      .first())
  )
    return discordError(context, 403, 50001, "Missing Access");
  if (context.req.method === "GET") {
    const rows = await context.env.IDENTITY_DB.prepare(
      `SELECT id,application_id,guild_id,type,payload_json,version
         FROM application_commands
        WHERE application_id=?1 AND guild_id IS ?2 ORDER BY created_at`,
    )
      .bind(applicationId, guildId)
      .all<{
        id: string;
        application_id: string;
        guild_id: string | null;
        type: number;
        payload_json: string;
        version: string;
      }>();
    return context.json(
      rows.results.map(discordApplicationCommand),
      200,
      discordRateLimitHeaders(),
    );
  }
  const raw = await context.req.json<unknown>().catch(() => null);
  const inputs = context.req.method === "PUT" ? raw : [raw];
  if (!Array.isArray(inputs))
    return discordError(context, 400, 50035, "Invalid Form Body");
  const normalized = inputs.map(normalizeDiscordCommand);
  if (normalized.some((command) => command === null))
    return discordError(context, 400, 50035, "Invalid Form Body");
  const timestamp = nowIso();
  const statements: D1PreparedStatement[] = [];
  if (context.req.method === "PUT")
    statements.push(
      context.env.IDENTITY_DB.prepare(
        "DELETE FROM application_commands WHERE application_id=?1 AND guild_id IS ?2",
      ).bind(applicationId, guildId),
    );
  const results: ReturnType<typeof discordApplicationCommand>[] = [];
  for (const command of normalized as DiscordCommandInput[]) {
    const type = command.type ?? 1;
    const existing =
      context.req.method === "POST"
        ? await context.env.IDENTITY_DB.prepare(
            `SELECT id,created_at FROM application_commands
              WHERE application_id=?1 AND guild_id IS ?2 AND type=?3 AND name=?4`,
          )
            .bind(applicationId, guildId, type, command.name)
            .first<{ id: string; created_at: string }>()
        : null;
    const id = existing?.id ?? (await generateId(context.env, applicationId));
    const version = await generateId(context.env, id);
    const payload = JSON.stringify(command);
    statements.push(
      context.env.IDENTITY_DB.prepare(
        `INSERT INTO application_commands(
           id,application_id,guild_id,type,name,description,payload_json,version,created_at,updated_at
         ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)
         ON CONFLICT(id) DO UPDATE SET type=excluded.type,name=excluded.name,
           description=excluded.description,payload_json=excluded.payload_json,
           version=excluded.version,updated_at=excluded.updated_at`,
      ).bind(
        id,
        applicationId,
        guildId,
        type,
        command.name,
        command.description ?? "",
        payload,
        version,
        existing?.created_at ?? timestamp,
        timestamp,
      ),
    );
    results.push(
      discordApplicationCommand({
        id,
        application_id: applicationId,
        guild_id: guildId,
        type,
        payload_json: payload,
        version,
      }),
    );
  }
  await context.env.IDENTITY_DB.batch(statements);
  return context.json(
    context.req.method === "POST" ? results[0] : results,
    context.req.method === "POST" ? 201 : 200,
    discordRateLimitHeaders(),
  );
}

async function handleDiscordCommand(
  context: Context<Application>,
  guildId: string | null,
) {
  const bot = await authenticateBot(context.env, context.req.raw);
  if (!bot) return discordError(context, 401, 0, "401: Unauthorized");
  const applicationId = context.req.param("applicationId");
  if (applicationId !== bot.applicationId)
    return discordError(context, 403, 50001, "Missing Access");
  const commandId = context.req.param("commandId");
  const row = await context.env.IDENTITY_DB.prepare(
    `SELECT id,application_id,guild_id,type,payload_json,version
       FROM application_commands
      WHERE id=?1 AND application_id=?2 AND guild_id IS ?3`,
  )
    .bind(commandId, applicationId, guildId)
    .first<{
      id: string;
      application_id: string;
      guild_id: string | null;
      type: number;
      payload_json: string;
      version: string;
    }>();
  if (!row)
    return discordError(context, 404, 10063, "Unknown Application Command");
  if (context.req.method === "GET")
    return context.json(
      discordApplicationCommand(row),
      200,
      discordRateLimitHeaders(),
    );
  if (context.req.method === "DELETE") {
    await context.env.IDENTITY_DB.prepare(
      "DELETE FROM application_commands WHERE id=?1",
    )
      .bind(commandId)
      .run();
    return new Response(null, {
      status: 204,
      headers: discordRateLimitHeaders(),
    });
  }
  const current = JSON.parse(row.payload_json) as DiscordCommandInput;
  const patch = await context.req.json<DiscordCommandInput>().catch(() => null);
  const command = patch
    ? normalizeDiscordCommand({ ...current, ...patch })
    : null;
  if (!command) return discordError(context, 400, 50035, "Invalid Form Body");
  const version = await generateId(context.env, commandId!);
  const payload = JSON.stringify(command);
  await context.env.IDENTITY_DB.prepare(
    `UPDATE application_commands SET type=?1,name=?2,description=?3,
       payload_json=?4,version=?5,updated_at=?6 WHERE id=?7`,
  )
    .bind(
      command.type ?? 1,
      command.name,
      command.description ?? "",
      payload,
      version,
      nowIso(),
      commandId,
    )
    .run();
  return context.json(
    discordApplicationCommand({ ...row, payload_json: payload, version }),
    200,
    discordRateLimitHeaders(),
  );
}

function normalizeDiscordCommand(input: unknown): DiscordCommandInput | null {
  if (!input || typeof input !== "object" || Array.isArray(input)) return null;
  const value = input as DiscordCommandInput;
  const type = value.type ?? 1;
  if (
    ![1, 2, 3].includes(type) ||
    !value.name ||
    value.name.length > 32 ||
    !/^[\p{Ll}\p{Lm}\p{Lo}\p{N}_-]+$/u.test(value.name) ||
    (type === 1 && (!value.description || value.description.length > 100)) ||
    (value.options !== undefined && !Array.isArray(value.options))
  )
    return null;
  if (
    value.default_member_permissions !== undefined &&
    value.default_member_permissions !== null &&
    parsePermissionBits(value.default_member_permissions) === null
  )
    return null;
  return {
    ...value,
    type,
    description: type === 1 ? value.description! : "",
    options: value.options ?? [],
  };
}

function discordApplicationCommand(row: {
  id: string;
  application_id: string;
  guild_id: string | null;
  type: number;
  payload_json: string;
  version: string;
}) {
  const payload = JSON.parse(row.payload_json) as DiscordCommandInput;
  return {
    id: row.id,
    application_id: row.application_id,
    guild_id: row.guild_id ?? undefined,
    version: row.version,
    ...payload,
    type: row.type,
  };
}

function discordMessage(message: Record<string, unknown>) {
  const author = message.author as {
    id: string;
    username: string;
    displayName: string;
    bot?: boolean;
  };
  const poll = message.poll as
    | {
        question: string;
        expiresAt: string;
        allowMultiselect: boolean;
        answers: Array<{
          id: string;
          text: string;
          voteCount: number;
          meVoted: boolean;
        }>;
      }
    | null
    | undefined;
  return {
    id: message.id,
    channel_id: message.channelId,
    author: {
      id: author.id,
      username: author.username,
      global_name: author.displayName,
      discriminator: "0000",
      avatar: null,
      bot: author.bot ?? true,
    },
    content: message.content,
    timestamp: message.createdAt,
    edited_timestamp: message.editedAt,
    tts: false,
    mention_everyone: false,
    mentions: [],
    mention_roles: [],
    attachments: Array.isArray(message.attachments)
      ? message.attachments.map((attachment) => {
          const value = attachment as Record<string, unknown>;
          return {
            id: value.id,
            filename: value.filename,
            size: value.size,
            url: value.url,
            proxy_url: value.url,
            content_type: value.contentType,
          };
        })
      : [],
    embeds: [],
    pinned: message.pinned,
    reactions: Array.isArray(message.reactions)
      ? message.reactions.map((reaction) => {
          const value = reaction as Record<string, unknown>;
          return {
            count: value.count,
            me: value.me,
            emoji: { id: null, name: value.emoji },
          };
        })
      : [],
    message_reference: message.replyToId
      ? { message_id: message.replyToId, channel_id: message.channelId }
      : undefined,
    poll: poll
      ? {
          question: { text: poll.question },
          answers: poll.answers.map((answer) => ({
            answer_id: Number(answer.id),
            poll_media: { text: answer.text },
          })),
          expiry: poll.expiresAt,
          allow_multiselect: poll.allowMultiselect,
          layout_type: 1,
          results: {
            is_finalized: false,
            answer_counts: poll.answers.map((answer) => ({
              id: Number(answer.id),
              count: answer.voteCount,
              me_voted: answer.meVoted,
            })),
          },
        }
      : undefined,
    type: 0,
  };
}

interface DiscordThreadInput {
  name?: string;
  type?: number;
  auto_archive_duration?: number;
  message?: { content?: string };
}

async function createDiscordThread(
  context: Context<Application>,
  parent: ChannelAccess,
  bot: { userId: string; username: string },
  body: DiscordThreadInput | null,
) {
  if (
    parent.guild_id.startsWith("dm:") ||
    ![
      "GUILD_TEXT",
      "GUILD_ANNOUNCEMENT",
      "GUILD_FORUM",
      "GUILD_MEDIA",
    ].includes(parent.type)
  )
    return discordError(context, 400, 50035, "Invalid Form Body");
  const privateThread = body?.type === 12;
  const requiredPermission = privateThread
    ? PermissionFlags.CREATE_PRIVATE_THREADS
    : PermissionFlags.CREATE_PUBLIC_THREADS;
  if (!hasPermission(parent.permissions, requiredPermission))
    return discordError(context, 403, 50013, "Missing Permissions");
  const autoArchive = body?.auto_archive_duration ?? 1440;
  if (
    !body?.name ||
    body.name.length > 100 ||
    ![60, 1440, 4320, 10080].includes(autoArchive) ||
    (body.message?.content?.length ?? 0) > 4000 ||
    (body.type !== undefined && ![10, 11, 12].includes(body.type))
  )
    return discordError(context, 400, 50035, "Invalid Form Body");
  const type =
    parent.type === "GUILD_ANNOUNCEMENT"
      ? "ANNOUNCEMENT_THREAD"
      : privateThread
        ? "PRIVATE_THREAD"
        : "PUBLIC_THREAD";
  const id = await generateId(context.env, parent.id);
  const createdAt = nowIso();
  const guild = await guildDatabase(context.env, parent.guild_id);
  const position = await guild.db
    .prepare(
      "SELECT coalesce(max(position),-1)+1 AS value FROM channels WHERE guild_id=?1",
    )
    .bind(parent.guild_id)
    .first<{ value: number }>();
  await guild.db.batch([
    guild.db
      .prepare(
        `INSERT INTO channels(id,guild_id,parent_id,type,name,position,created_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7)`,
      )
      .bind(
        id,
        parent.guild_id,
        parent.id,
        type,
        body.name,
        position?.value ?? 0,
        createdAt,
      ),
    guild.db
      .prepare(
        `INSERT INTO thread_metadata(channel_id,owner_id,auto_archive_minutes,created_at)
         VALUES (?1,?2,?3,?4)`,
      )
      .bind(id, bot.userId, autoArchive, createdAt),
    guild.db
      .prepare(
        "INSERT INTO thread_members(channel_id,user_id,joined_at) VALUES (?1,?2,?3)",
      )
      .bind(id, bot.userId, createdAt),
    guild.db
      .prepare(
        `INSERT INTO permission_overwrites(channel_id,target_id,target_type,allow_bits,deny_bits)
         SELECT ?1,target_id,target_type,allow_bits,deny_bits
           FROM permission_overwrites WHERE channel_id=?2`,
      )
      .bind(id, parent.id),
  ]);
  await registerResource(
    context.env,
    id,
    "guild_channel",
    parent.guild_id,
    createdAt,
  );
  let message: Record<string, unknown> | undefined;
  if (body.message?.content) {
    const messageId = await generateId(context.env, id);
    const response = await channelStub(context.env, id).fetch(
      new Request("https://do/messages", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          id: messageId,
          channelId: id,
          authorId: bot.userId,
          authorUsername: bot.username,
          authorDisplayName: bot.username,
          authorBot: true,
          content: body.message.content,
          createdAt,
          replyToId: null,
          attachments: [],
          partitionKey: parent.guild_id,
          slowmodeSeconds: 0,
          bypassSlowmode: true,
        }),
      }),
    );
    if (response.ok)
      message = discordMessage(await response.json<Record<string, unknown>>());
  }
  const channel = await discordChannel(context.env, id, bot.userId);
  return context.json(
    { ...channel, ...(message ? { message } : {}) },
    201,
    discordRateLimitHeaders(),
  );
}

async function discordChannel(env: Env, channelId: string, viewerId: string) {
  const access = await accessibleChannel(env, channelId, viewerId);
  if (!access) return null;
  if (access.guild_id.startsWith("dm:"))
    return {
      id: access.id,
      type: access.type === "DM" ? 1 : 3,
      last_message_id: null,
      recipients: [],
    };
  const guild = await guildDatabase(env, access.guild_id);
  const row = await guild.db
    .prepare(
      `SELECT id,guild_id,parent_id,type,name,topic,position,slowmode_seconds,last_message_id
         FROM channels WHERE id=?1`,
    )
    .bind(channelId)
    .first<{
      id: string;
      guild_id: string;
      parent_id: string | null;
      type: string;
      name: string;
      topic: string | null;
      position: number;
      slowmode_seconds: number;
      last_message_id: string | null;
    }>();
  if (!row) return null;
  const overwrites = await guild.db
    .prepare(
      `SELECT target_id,target_type,allow_bits,deny_bits
         FROM permission_overwrites WHERE channel_id=?1`,
    )
    .bind(channelId)
    .all<{
      target_id: string;
      target_type: "role" | "member";
      allow_bits: string;
      deny_bits: string;
    }>();
  return {
    id: row.id,
    type: discordChannelType(row.type),
    guild_id: row.guild_id,
    position: row.position,
    permission_overwrites: overwrites.results.map((overwrite) => ({
      id: overwrite.target_id,
      type: overwrite.target_type === "role" ? 0 : 1,
      allow: overwrite.allow_bits,
      deny: overwrite.deny_bits,
    })),
    name: row.name,
    topic: row.topic,
    nsfw: false,
    last_message_id: row.last_message_id,
    parent_id: row.parent_id,
    rate_limit_per_user: row.slowmode_seconds,
  };
}

function discordChannelType(type: string): number {
  return (
    (
      {
        GUILD_TEXT: 0,
        DM: 1,
        GUILD_VOICE: 2,
        GROUP_DM: 3,
        GUILD_CATEGORY: 4,
        GUILD_ANNOUNCEMENT: 5,
        ANNOUNCEMENT_THREAD: 10,
        PUBLIC_THREAD: 11,
        PRIVATE_THREAD: 12,
        GUILD_STAGE_VOICE: 13,
        GUILD_DIRECTORY: 14,
        GUILD_FORUM: 15,
        GUILD_MEDIA: 16,
      } as Record<string, number>
    )[type] ?? 0
  );
}

function discordRateLimitHeaders(): Record<string, string> {
  return { "x-ratelimit-scope": "shared" };
}

function parsePermissionBits(value: string): bigint | null {
  try {
    const parsed = BigInt(value);
    return parsed >= 0n && (parsed & ~ALL_PERMISSIONS) === 0n ? parsed : null;
  } catch {
    return null;
  }
}

function discordError(
  context: Parameters<typeof apiError>[0],
  status: 400 | 401 | 403 | 404 | 405 | 409 | 429,
  code: number,
  message: string,
) {
  return context.json({ code, message }, status);
}

export default {
  fetch: app.fetch,
  queue: processQueue,
  async scheduled(controller: ScheduledController, env: Env): Promise<void> {
    const timestamp = nowIso();
    if (
      controller.cron === "0 3 * * 0" &&
      env.CLOUDFLARE_ACCOUNT_ID &&
      (await getOptionalSecret(env, "CLOUDFLARE_BACKUP_API_TOKEN"))
    ) {
      const backupId = timestamp.slice(0, 10);
      try {
        await env.BACKUP_WORKFLOW.create({
          id: `weekly-${backupId}`,
          params: { backupId },
        });
      } catch (cause) {
        console.warn(
          JSON.stringify({
            event: "backup_workflow_not_started",
            backupId,
            error: cause instanceof Error ? cause.message : String(cause),
          }),
        );
      }
    }
    await dispatchIdentityOutbox(
      env,
      await getSecret(env, "DATA_ENCRYPTION_KEY"),
    );
    const expired = await env.IDENTITY_DB.prepare(
      "SELECT object_key FROM media_objects WHERE state='pending' AND expires_at < ?1 LIMIT 100",
    )
      .bind(timestamp)
      .all<{ object_key: string }>();
    for (const object of expired.results)
      await env.MEDIA.delete(object.object_key);
    const oldBackups = await env.RELEASES.list({
      prefix: "backups/",
      limit: 1000,
    });
    const backupCutoff = Date.now() - 90 * 24 * 60 * 60_000;
    const expiredBackupKeys = oldBackups.objects
      .filter((object) => object.uploaded.getTime() < backupCutoff)
      .map((object) => object.key);
    if (expiredBackupKeys.length > 0)
      await env.RELEASES.delete(expiredBackupKeys);
    const exportRetentionDays = await configNumber(
      env,
      "export.retention_days",
      7,
    );
    const expiredExports = await env.IDENTITY_DB.prepare(
      `SELECT id,user_id FROM account_lifecycle_jobs
        WHERE kind='export' AND phase='complete'
          AND updated_at<datetime('now',?1) LIMIT 20`,
    )
      .bind(`-${exportRetentionDays} days`)
      .all<{ id: string; user_id: string }>();
    for (const job of expiredExports.results) {
      let cursor: string | undefined;
      do {
        const objects = await env.MEDIA.list({
          prefix: `exports/${job.user_id}/${job.id}/`,
          limit: 1000,
          ...(cursor ? { cursor } : {}),
        });
        if (objects.objects.length > 0)
          await env.MEDIA.delete(objects.objects.map((object) => object.key));
        cursor = objects.truncated ? objects.cursor : undefined;
      } while (cursor);
      await env.IDENTITY_DB.prepare(
        `UPDATE account_lifecycle_jobs
            SET phase='expired',object_key=NULL,updated_at=?1 WHERE id=?2`,
      )
        .bind(timestamp, job.id)
        .run();
    }
    await env.IDENTITY_DB.prepare(
      "DELETE FROM media_objects WHERE state='pending' AND expires_at < ?1",
    )
      .bind(timestamp)
      .run();
    await env.IDENTITY_DB.batch([
      env.IDENTITY_DB.prepare(
        "DELETE FROM auth_challenges WHERE expires_at<?1",
      ).bind(timestamp),
      env.IDENTITY_DB.prepare(
        "DELETE FROM one_time_tokens WHERE expires_at<?1 AND consumed_at IS NOT NULL",
      ).bind(timestamp),
      env.IDENTITY_DB.prepare(
        "DELETE FROM idempotency_keys WHERE expires_at<?1",
      ).bind(timestamp),
      env.IDENTITY_DB.prepare(
        "DELETE FROM sessions WHERE expires_at<?1 AND revoked_at IS NOT NULL",
      ).bind(timestamp),
      env.IDENTITY_DB.prepare(
        "DELETE FROM transactional_outbox WHERE delivered_at IS NOT NULL AND delivered_at<datetime('now','-7 days')",
      ),
      env.IDENTITY_DB.prepare(
        "DELETE FROM queue_receipts WHERE processed_at<datetime('now','-30 days')",
      ),
      env.IDENTITY_DB.prepare(
        "DELETE FROM account_lifecycle_jobs WHERE phase IN ('expired','errored') AND updated_at<datetime('now','-30 days')",
      ),
      env.IDENTITY_DB.prepare(
        "DELETE FROM interaction_tokens WHERE expires_at<?1",
      ).bind(timestamp),
      env.IDENTITY_DB.prepare(
        "DELETE FROM desktop_auth_codes WHERE expires_at<?1",
      ).bind(timestamp),
      env.IDENTITY_DB.prepare(
        "DELETE FROM voice_usage WHERE ended_at<datetime('now','-90 days')",
      ),
    ]);
    for (let bucket = 0; bucket < 32; bucket += 1) {
      const binding = `GUILD_DB_${String(bucket).padStart(2, "0")}`;
      const db = databaseBinding(env, binding);
      await db
        .prepare(
          `UPDATE thread_metadata
              SET archived=1,archived_at=?1
            WHERE archived=0
              AND datetime(created_at,'+' || auto_archive_minutes || ' minutes')<=?1`,
        )
        .bind(timestamp)
        .run();
    }
  },
};

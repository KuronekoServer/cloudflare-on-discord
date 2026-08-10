import { sha256, verifyAccessToken } from "@cloudcord/core";
import { createMiddleware } from "hono/factory";
import type { AppVariables, AuthUser, Env } from "./env";
import { apiError } from "./http";
import { getOptionalSecret, getSecret } from "./secrets";

export const requireAuth = createMiddleware<{
  Bindings: Env;
  Variables: AppVariables;
}>(async (context, next) => {
  const authorization = context.req.header("authorization");
  const token = authorization?.startsWith("Bearer ")
    ? authorization.slice(7)
    : undefined;
  const socketTicket = context.req.query("ticket");
  if (!token && !socketTicket)
    return apiError(context, 401, "UNAUTHORIZED", "Bearer token required");

  try {
    if (!token && socketTicket) {
      const ticketHash = await sha256(socketTicket);
      const record = await context.env.IDENTITY_DB.prepare(
        `SELECT c.id, c.user_id, u.username, u.display_name
           FROM auth_challenges c JOIN users u ON u.id=c.user_id
          WHERE c.kind='websocket_ticket' AND c.challenge_hash=?1 AND c.consumed_at IS NULL AND c.expires_at>?2`,
      )
        .bind(ticketHash, new Date().toISOString())
        .first<{
          id: string;
          user_id: string;
          username: string;
          display_name: string;
        }>();
      if (!record)
        return apiError(
          context,
          401,
          "INVALID_SOCKET_TICKET",
          "WebSocket ticket is invalid or expired",
        );
      const consumed = await context.env.IDENTITY_DB.prepare(
        "UPDATE auth_challenges SET consumed_at=?1 WHERE id=?2 AND consumed_at IS NULL",
      )
        .bind(new Date().toISOString(), record.id)
        .run();
      if (consumed.meta.changes !== 1)
        return apiError(
          context,
          401,
          "SOCKET_TICKET_REUSED",
          "WebSocket ticket was already used",
        );
      context.set("auth", {
        id: record.user_id,
        sessionId: "websocket-ticket",
        username: record.username,
        displayName: record.display_name,
      });
      await next();
      return;
    }
    const signingKey = await getSecret(context.env, "JWT_SIGNING_KEY");
    const claims = await verifyAccessToken(token!, signingKey);
    const session = await context.env.IDENTITY_DB.prepare(
      "SELECT id FROM sessions WHERE id = ?1 AND user_id = ?2 AND revoked_at IS NULL AND expires_at > ?3",
    )
      .bind(claims.sid, claims.sub, new Date().toISOString())
      .first<{ id: string }>();
    if (!session)
      return apiError(
        context,
        401,
        "SESSION_REVOKED",
        "Session is no longer valid",
      );
    const auth: AuthUser = {
      id: claims.sub,
      sessionId: claims.sid,
      username: String(claims.username),
      displayName: String(claims.displayName),
    };
    context.set("auth", auth);
    await next();
  } catch {
    return apiError(
      context,
      401,
      "INVALID_TOKEN",
      "Access token is invalid or expired",
    );
  }
});

export async function verifyTurnstile(
  env: Env,
  token: string,
  remoteIp?: string,
): Promise<boolean> {
  const bypass = await getOptionalSecret(env, "TURNSTILE_BYPASS_TOKEN");
  if (env.ENVIRONMENT === "dev" && bypass && token === bypass) return true;
  const body = new FormData();
  body.set("secret", await getSecret(env, "TURNSTILE_SECRET"));
  body.set("response", token);
  if (remoteIp) body.set("remoteip", remoteIp);
  const response = await fetch(
    "https://challenges.cloudflare.com/turnstile/v0/siteverify",
    { method: "POST", body },
  );
  if (!response.ok) return false;
  const result = await response.json<{ success: boolean }>();
  return result.success;
}

export async function clientIpHmac(
  env: Env,
  request: Request,
): Promise<string | null> {
  const ip = request.headers.get("cf-connecting-ip");
  return ip ? sha256(`${await getSecret(env, "LOOKUP_HMAC_KEY")}:${ip}`) : null;
}

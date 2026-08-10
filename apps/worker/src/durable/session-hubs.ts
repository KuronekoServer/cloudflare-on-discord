import type { Env } from "../env";
import { broadcast, upgradeWebSocket } from "./shared";

abstract class EventHub {
  constructor(
    protected readonly state: DurableObjectState,
    _env: Env,
  ) {}

  fetch(request: Request): Response | Promise<Response> {
    return upgradeWebSocket(this.state, request);
  }

  webSocketMessage(socket: WebSocket, message: string | ArrayBuffer): void {
    if (typeof message !== "string") return;
    try {
      const value = JSON.parse(message) as {
        op?: number;
        event?: string;
        data?: unknown;
      };
      if (value.op === 1)
        socket.send(JSON.stringify({ op: 2, data: { at: Date.now() } }));
      else broadcast(this.state, value, socket);
    } catch {
      socket.close(4002, "Invalid payload");
    }
  }
}

export class GuildPresenceDO extends EventHub {}
export class UserSessionDO extends EventHub {
  private readonly sql: SqlStorage;

  constructor(state: DurableObjectState, env: Env) {
    super(state, env);
    this.sql = state.storage.sql;
    this.sql.exec(`CREATE TABLE IF NOT EXISTS rate_limits (
      scope TEXT NOT NULL,
      bucket INTEGER NOT NULL,
      count INTEGER NOT NULL,
      PRIMARY KEY(scope,bucket)
    )`);
  }

  override async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname !== "/rate-limit" || request.method !== "POST")
      return super.fetch(request);
    const input = await request.json<{
      scope?: string;
      limit?: number;
      windowMs?: number;
    }>();
    const scope = String(input.scope ?? "").slice(0, 128);
    const limit = Math.min(Math.max(Math.floor(input.limit ?? 1), 1), 10_000);
    const windowMs = Math.min(
      Math.max(Math.floor(input.windowMs ?? 60_000), 1_000),
      86_400_000,
    );
    if (!scope)
      return Response.json(
        { allowed: false, retryAfterMs: windowMs },
        { status: 400 },
      );
    const now = Date.now();
    const bucket = Math.floor(now / windowMs);
    const resetAt = (bucket + 1) * windowMs;
    const count = this.state.storage.transactionSync(() => {
      this.sql.exec(
        `INSERT INTO rate_limits(scope,bucket,count) VALUES (?,?,1)
         ON CONFLICT(scope,bucket) DO UPDATE SET count=count+1`,
        scope,
        bucket,
      );
      const current = this.sql
        .exec<{ count: number }>(
          "SELECT count FROM rate_limits WHERE scope=? AND bucket=?",
          scope,
          bucket,
        )
        .one().count;
      this.sql.exec("DELETE FROM rate_limits WHERE bucket<?", bucket - 2);
      return current;
    });
    return Response.json({
      allowed: count <= limit,
      limit,
      remaining: Math.max(limit - count, 0),
      resetAt,
      retryAfterMs: Math.max(resetAt - now, 0),
    });
  }
}

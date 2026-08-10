import { sha256 } from "@cloudcord/core";
import type { Env } from "../env";

interface GatewayAttachment {
  sessionId?: string;
  botUserId?: string;
  intents?: string;
  shardId?: number;
  shardCount?: number;
  sequence: number;
  identified: boolean;
}

export class BotGatewayShardDO {
  private readonly sql: SqlStorage;

  constructor(
    private readonly state: DurableObjectState,
    private readonly env: Env,
  ) {
    this.sql = state.storage.sql;
    this.sql.exec(`CREATE TABLE IF NOT EXISTS gateway_sessions (
      session_id TEXT PRIMARY KEY,
      bot_user_id TEXT NOT NULL,
      sequence INTEGER NOT NULL,
      intents TEXT NOT NULL,
      shard_id INTEGER NOT NULL,
      shard_count INTEGER NOT NULL,
      expires_at TEXT NOT NULL
    )`);
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === "POST" && url.pathname.endsWith("/dispatch")) {
      const input = await request.json<{
        event: string;
        data: Record<string, unknown>;
        targetBotIds: string[];
        requiredIntent: string;
        guildId?: string;
      }>();
      const targets = new Set(input.targetBotIds);
      let delivered = 0;
      for (const socket of this.state.getWebSockets()) {
        const attachment = socket.deserializeAttachment() as GatewayAttachment;
        if (
          !attachment?.identified ||
          !attachment.botUserId ||
          !targets.has(attachment.botUserId) ||
          (BigInt(input.requiredIntent) !== 0n &&
            (BigInt(attachment.intents ?? "0") &
              BigInt(input.requiredIntent)) ===
              0n)
        )
          continue;
        if (
          input.guildId &&
          attachment.shardCount &&
          Number(
            (BigInt(input.guildId) >> 22n) % BigInt(attachment.shardCount),
          ) !== attachment.shardId
        )
          continue;
        attachment.sequence += 1;
        socket.serializeAttachment(attachment);
        this.sql.exec(
          "UPDATE gateway_sessions SET sequence=?,expires_at=? WHERE session_id=?",
          attachment.sequence,
          new Date(Date.now() + 5 * 60_000).toISOString(),
          attachment.sessionId ?? "",
        );
        socket.send(
          JSON.stringify({
            op: 0,
            t: input.event,
            s: attachment.sequence,
            d: input.data,
          }),
        );
        delivered += 1;
      }
      return Response.json({ delivered });
    }
    if (request.headers.get("upgrade")?.toLowerCase() !== "websocket")
      return new Response("WebSocket upgrade required", { status: 426 });
    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    this.state.acceptWebSocket(server);
    server.serializeAttachment({
      sequence: 0,
      identified: false,
    } satisfies GatewayAttachment);
    server.send(
      JSON.stringify({
        op: 10,
        d: { heartbeat_interval: 41_250, _trace: ["cloudcord-gateway"] },
      }),
    );
    return new Response(null, { status: 101, webSocket: client });
  }

  async webSocketMessage(
    socket: WebSocket,
    raw: string | ArrayBuffer,
  ): Promise<void> {
    if (typeof raw !== "string")
      return socket.close(4002, "Binary gateway requires ETF decoder adapter");
    try {
      const payload = JSON.parse(raw) as {
        op: number;
        d?: Record<string, unknown>;
      };
      const attachment =
        (socket.deserializeAttachment() as GatewayAttachment | null) ?? {
          sequence: 0,
          identified: false,
        };
      if (payload.op === 1)
        return socket.send(JSON.stringify({ op: 11, d: null }));
      if (payload.op === 2) {
        const token =
          typeof payload.d?.token === "string" ? payload.d.token : "";
        const bot = await this.env.IDENTITY_DB.prepare(
          `SELECT u.id,u.username,b.intents FROM bots b JOIN users u ON u.id=b.user_id
            WHERE b.token_hash=?1 AND b.enabled=1`,
        )
          .bind(await sha256(token))
          .first<{ id: string; username: string; intents: string }>();
        if (!bot) return socket.close(4004, "Authentication failed");
        const requestedIntents = BigInt(String(payload.d?.intents ?? "0"));
        if ((requestedIntents & ~BigInt(bot.intents)) !== 0n)
          return socket.close(4014, "Disallowed intents");
        const sessionId = crypto.randomUUID();
        const shard = Array.isArray(payload.d?.shard)
          ? (payload.d.shard as unknown[])
          : [0, 1];
        const shardId = Math.max(Number(shard[0] ?? 0), 0);
        const shardCount = Math.max(Number(shard[1] ?? 1), 1);
        const updated = {
          sessionId,
          botUserId: bot.id,
          intents: requestedIntents.toString(),
          shardId,
          shardCount,
          sequence: 1,
          identified: true,
        } satisfies GatewayAttachment;
        socket.serializeAttachment(updated);
        this.sql.exec(
          `INSERT INTO gateway_sessions(session_id,bot_user_id,sequence,intents,shard_id,shard_count,expires_at)
           VALUES (?,?,?,?,?,?,?)`,
          sessionId,
          bot.id,
          1,
          requestedIntents.toString(),
          shardId,
          shardCount,
          new Date(Date.now() + 5 * 60_000).toISOString(),
        );
        socket.send(
          JSON.stringify({
            op: 0,
            t: "READY",
            s: 1,
            d: {
              v: 10,
              session_id: sessionId,
              resume_gateway_url: new URL(
                "/api/v10/gateway",
                "https://gateway.invalid",
              ).toString(),
              user: { id: bot.id, username: bot.username, bot: true },
              guilds: [],
            },
          }),
        );
        return;
      }
      if (payload.op === 6) {
        const token =
          typeof payload.d?.token === "string" ? payload.d.token : "";
        const sessionId =
          typeof payload.d?.session_id === "string" ? payload.d.session_id : "";
        const sequence = Number(payload.d?.seq ?? 0);
        const bot = await this.env.IDENTITY_DB.prepare(
          "SELECT user_id FROM bots WHERE token_hash=?1 AND enabled=1",
        )
          .bind(await sha256(token))
          .first<{ user_id: string }>();
        const session = this.sql
          .exec<{
            bot_user_id: string;
            sequence: number;
            intents: string;
            shard_id: number;
            shard_count: number;
          }>(
            `SELECT bot_user_id,sequence,intents,shard_id,shard_count
               FROM gateway_sessions WHERE session_id=? AND expires_at>?`,
            sessionId,
            new Date().toISOString(),
          )
          .toArray()[0];
        if (!bot || !session || bot.user_id !== session.bot_user_id)
          return socket.send(JSON.stringify({ op: 9, d: false }));
        const resumed = {
          sessionId,
          botUserId: session.bot_user_id,
          intents: session.intents,
          shardId: session.shard_id,
          shardCount: session.shard_count,
          sequence: Math.max(sequence, session.sequence) + 1,
          identified: true,
        } satisfies GatewayAttachment;
        socket.serializeAttachment(resumed);
        this.sql.exec(
          "UPDATE gateway_sessions SET sequence=?,expires_at=? WHERE session_id=?",
          resumed.sequence,
          new Date(Date.now() + 5 * 60_000).toISOString(),
          sessionId,
        );
        socket.send(
          JSON.stringify({
            op: 0,
            t: "RESUMED",
            s: resumed.sequence,
            d: {},
          }),
        );
        return;
      }
      if (payload.op === 3 || payload.op === 4) return;
      socket.send(JSON.stringify({ op: 9, d: false }));
    } catch {
      socket.close(4002, "Invalid payload");
    }
  }
}

import { selectVoiceSubscriptions, type VoiceCandidate } from "@cloudcord/core";
import type { Env } from "../env";
import { broadcast, json, readJson, upgradeWebSocket } from "./shared";

interface ParticipantInput {
  channelId: string;
  userId: string;
  displayName: string;
  muted: boolean;
  deafened: boolean;
  camera: boolean;
}

interface PublishedTrack {
  trackName: string;
  kind: "audio" | "video";
  label: "microphone" | "camera" | "screen";
}

export class VoiceRoomDO {
  private readonly sql: SqlStorage;
  private readonly roomLimit: number;
  private readonly screenLimit: number;

  constructor(
    private readonly state: DurableObjectState,
    private readonly env: Env,
  ) {
    this.sql = state.storage.sql;
    this.roomLimit = Number(env.VOICE_ROOM_LIMIT || 50);
    this.screenLimit = Number(env.VOICE_SCREEN_SHARE_LIMIT || 5);
    this.sql.exec(`CREATE TABLE IF NOT EXISTS participants (
      user_id TEXT PRIMARY KEY,
      display_name TEXT NOT NULL,
      muted INTEGER NOT NULL,
      deafened INTEGER NOT NULL,
      camera INTEGER NOT NULL,
      screen INTEGER NOT NULL DEFAULT 0,
      priority INTEGER NOT NULL DEFAULT 0,
      level REAL NOT NULL DEFAULT 0,
      speaking INTEGER NOT NULL DEFAULT 0,
      last_spoke_at INTEGER NOT NULL DEFAULT 0,
      joined_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    )`);
    const columns = new Set(
      this.sql
        .exec<{ name: string }>("PRAGMA table_info(participants)")
        .toArray()
        .map((column) => column.name),
    );
    if (!columns.has("session_id"))
      this.sql.exec("ALTER TABLE participants ADD COLUMN session_id TEXT");
    if (!columns.has("published_tracks_json"))
      this.sql.exec(
        "ALTER TABLE participants ADD COLUMN published_tracks_json TEXT NOT NULL DEFAULT '[]'",
      );
    if (!columns.has("channel_id"))
      this.sql.exec("ALTER TABLE participants ADD COLUMN channel_id TEXT");
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (request.headers.get("upgrade")?.toLowerCase() === "websocket") {
      const userId = url.searchParams.get("user");
      if (!userId) return new Response("user is required", { status: 400 });
      const participant = this.sql
        .exec<{ user_id: string }>(
          "SELECT user_id FROM participants WHERE user_id = ?",
          userId,
        )
        .toArray()[0];
      if (!participant)
        return new Response("Join the room first", { status: 403 });
      return upgradeWebSocket(this.state, request, [`user:${userId}`]);
    }

    if (url.pathname.endsWith("/session")) {
      if (request.method === "PUT") {
        const input = await readJson<{
          userId: string;
          sessionId: string;
        }>(request);
        const updated = this.sql.exec(
          "UPDATE participants SET session_id=?,published_tracks_json='[]',updated_at=? WHERE user_id=?",
          input.sessionId,
          new Date().toISOString(),
          input.userId,
        );
        if (updated.rowsWritten !== 1)
          return json({ code: "VOICE_PARTICIPANT_NOT_FOUND" }, { status: 404 });
        return new Response(null, { status: 204 });
      }
      if (request.method === "GET") {
        const userId = url.searchParams.get("user") ?? "";
        const sessionId = url.searchParams.get("session") ?? "";
        const present =
          this.sql
            .exec<{ present: number }>(
              "SELECT 1 AS present FROM participants WHERE user_id=? AND session_id=?",
              userId,
              sessionId,
            )
            .toArray().length === 1;
        return json({ present });
      }
    }
    if (request.method === "PUT" && url.pathname.endsWith("/tracks")) {
      const input = await readJson<{
        userId: string;
        sessionId: string;
        tracks: PublishedTrack[];
      }>(request);
      const row = this.sql
        .exec<{ published_tracks_json: string }>(
          "SELECT published_tracks_json FROM participants WHERE user_id=? AND session_id=?",
          input.userId,
          input.sessionId,
        )
        .toArray()[0];
      if (!row)
        return json({ code: "VOICE_SESSION_NOT_FOUND" }, { status: 404 });
      const current = JSON.parse(row.published_tracks_json) as PublishedTrack[];
      const merged = new Map(current.map((track) => [track.trackName, track]));
      for (const track of input.tracks) merged.set(track.trackName, track);
      this.sql.exec(
        "UPDATE participants SET published_tracks_json=?,updated_at=? WHERE user_id=?",
        JSON.stringify([...merged.values()]),
        new Date().toISOString(),
        input.userId,
      );
      this.broadcastSubscriptions(Date.now());
      return new Response(null, { status: 204 });
    }
    if (request.method === "DELETE" && url.pathname.endsWith("/tracks")) {
      const input = await readJson<{
        userId: string;
        sessionId: string;
        trackNames: string[];
      }>(request);
      const row = this.sql
        .exec<{ published_tracks_json: string }>(
          "SELECT published_tracks_json FROM participants WHERE user_id=? AND session_id=?",
          input.userId,
          input.sessionId,
        )
        .toArray()[0];
      if (!row)
        return json({ code: "VOICE_SESSION_NOT_FOUND" }, { status: 404 });
      const removed = new Set(input.trackNames);
      const tracks = (
        JSON.parse(row.published_tracks_json) as PublishedTrack[]
      ).filter((track) => !removed.has(track.trackName));
      this.sql.exec(
        "UPDATE participants SET published_tracks_json=?,updated_at=? WHERE user_id=?",
        JSON.stringify(tracks),
        new Date().toISOString(),
        input.userId,
      );
      this.broadcastSubscriptions(Date.now());
      return new Response(null, { status: 204 });
    }
    if (request.method === "GET") return json(this.snapshot());
    if (request.method === "POST" && url.pathname.endsWith("/join")) {
      const input = await readJson<ParticipantInput>(request);
      const count = this.sql
        .exec<{ count: number }>("SELECT count(*) AS count FROM participants")
        .one().count;
      const exists =
        this.sql
          .exec<{ present: number }>(
            "SELECT 1 AS present FROM participants WHERE user_id = ?",
            input.userId,
          )
          .toArray().length > 0;
      if (!exists && count >= this.roomLimit)
        return json({ code: "VOICE_ROOM_FULL" }, { status: 409 });
      const now = new Date().toISOString();
      this.sql.exec(
        `INSERT INTO participants(user_id, display_name, muted, deafened, camera, joined_at, updated_at, channel_id)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(user_id) DO UPDATE SET display_name=excluded.display_name, muted=excluded.muted,
           deafened=excluded.deafened, camera=excluded.camera, updated_at=excluded.updated_at,
           channel_id=excluded.channel_id`,
        input.userId,
        input.displayName,
        Number(input.muted),
        Number(input.deafened),
        Number(input.camera),
        now,
        now,
        input.channelId,
      );
      const snapshot = this.snapshot();
      broadcast(this.state, {
        op: 0,
        event: "VOICE_STATE_UPDATE",
        data: snapshot,
      });
      return json(snapshot, { status: 201 });
    }
    if (request.method === "DELETE") {
      const userId = url.searchParams.get("user");
      if (userId) await this.emitUsage(userId);
      this.sql.exec("DELETE FROM participants WHERE user_id = ?", userId ?? "");
      broadcast(this.state, {
        op: 0,
        event: "VOICE_STATE_UPDATE",
        data: this.snapshot(),
      });
      return new Response(null, { status: 204 });
    }
    return new Response("Method not allowed", { status: 405 });
  }

  webSocketMessage(socket: WebSocket, raw: string | ArrayBuffer): void {
    if (typeof raw !== "string") return;
    const userTag = this.state
      .getTags(socket)
      .find((tag) => tag.startsWith("user:"));
    const userId = userTag?.slice(5);
    if (!userId) return socket.close(4003, "Unknown participant");
    try {
      const message = JSON.parse(raw) as {
        op: number;
        data?: Record<string, unknown>;
      };
      if (message.op === 1)
        return socket.send(JSON.stringify({ op: 2, data: { at: Date.now() } }));
      if (message.op === 3) {
        const level = Math.min(
          Math.max(Number(message.data?.level ?? 0), 0),
          1,
        );
        const speaking = Boolean(message.data?.speaking);
        const now = Date.now();
        this.sql.exec(
          "UPDATE participants SET level=?, speaking=?, last_spoke_at=CASE WHEN ? THEN ? ELSE last_spoke_at END, updated_at=? WHERE user_id=?",
          level,
          Number(speaking),
          Number(speaking),
          now,
          new Date(now).toISOString(),
          userId,
        );
        this.broadcastSubscriptions(now);
      }
      if (message.op === 4) this.updateMediaState(userId, message.data ?? {});
    } catch {
      socket.close(4002, "Invalid payload");
    }
  }

  async webSocketClose(socket: WebSocket): Promise<void> {
    const userTag = this.state
      .getTags(socket)
      .find((tag) => tag.startsWith("user:"));
    if (userTag) {
      await this.emitUsage(userTag.slice(5));
      this.sql.exec(
        "DELETE FROM participants WHERE user_id = ?",
        userTag.slice(5),
      );
      broadcast(this.state, {
        op: 0,
        event: "VOICE_STATE_UPDATE",
        data: this.snapshot(),
      });
    }
  }

  private updateMediaState(
    userId: string,
    data: Record<string, unknown>,
  ): void {
    const requestedScreen = Boolean(data.screen);
    const current = this.sql
      .exec<{ screen: number }>(
        "SELECT screen FROM participants WHERE user_id = ?",
        userId,
      )
      .one();
    if (requestedScreen && !current.screen) {
      const screens = this.sql
        .exec<{ count: number }>(
          "SELECT count(*) AS count FROM participants WHERE screen = 1",
        )
        .one().count;
      if (screens >= this.screenLimit)
        throw new Error("Screen share limit reached");
    }
    this.sql.exec(
      "UPDATE participants SET muted=?, deafened=?, camera=?, screen=?, updated_at=? WHERE user_id=?",
      Number(Boolean(data.muted)),
      Number(Boolean(data.deafened)),
      Number(Boolean(data.camera)),
      Number(requestedScreen),
      new Date().toISOString(),
      userId,
    );
    broadcast(this.state, {
      op: 0,
      event: "VOICE_STATE_UPDATE",
      data: this.snapshot(),
    });
  }

  private async emitUsage(userId: string): Promise<void> {
    const row = this.sql
      .exec<{
        channel_id: string | null;
        session_id: string | null;
        joined_at: string;
        camera: number;
        screen: number;
        published_tracks_json: string;
      }>(
        `SELECT channel_id,session_id,joined_at,camera,screen,published_tracks_json
           FROM participants WHERE user_id=?`,
        userId,
      )
      .toArray()[0];
    if (!row?.channel_id) return;
    const endedAt = new Date();
    const durationSeconds = Math.max(
      Math.round((endedAt.getTime() - Date.parse(row.joined_at)) / 1000),
      0,
    );
    const tracks = JSON.parse(row.published_tracks_json) as PublishedTrack[];
    const audio = tracks.some((track) => track.label === "microphone");
    const camera =
      Boolean(row.camera) || tracks.some((track) => track.label === "camera");
    const screen =
      Boolean(row.screen) || tracks.some((track) => track.label === "screen");
    await this.env.EVENT_QUEUE.send({
      id: crypto.randomUUID(),
      topic: "voice.usage",
      partitionKey: row.channel_id,
      payload: {
        channelId: row.channel_id,
        userId,
        sessionId: row.session_id,
        startedAt: row.joined_at,
        endedAt: endedAt.toISOString(),
        durationSeconds,
        audioTrackSeconds: audio ? durationSeconds : 0,
        cameraTrackSeconds: camera ? durationSeconds : 0,
        screenTrackSeconds: screen ? durationSeconds : 0,
        estimatedSourceBytes: Math.round(
          durationSeconds *
            ((audio ? 32_000 / 8 : 0) +
              (camera ? 1_500_000 / 8 : 0) +
              (screen ? 3_000_000 / 8 : 0)),
        ),
      },
    });
  }

  private candidates(): VoiceCandidate[] {
    return this.sql
      .exec<Record<string, string | number>>(
        "SELECT user_id, level, speaking, last_spoke_at, priority FROM participants",
      )
      .toArray()
      .map((row) => ({
        userId: String(row.user_id),
        level: Number(row.level),
        speaking: Boolean(row.speaking),
        lastSpokeAt: Number(row.last_spoke_at),
        priority: Boolean(row.priority),
        pinned: false,
      }));
  }

  private broadcastSubscriptions(now: number): void {
    const candidates = this.candidates();
    const publishers = new Map(
      this.sql
        .exec<{
          user_id: string;
          session_id: string | null;
          published_tracks_json: string;
        }>(
          "SELECT user_id,session_id,published_tracks_json FROM participants WHERE session_id IS NOT NULL",
        )
        .toArray()
        .map((row) => [row.user_id, row]),
    );
    for (const socket of this.state.getWebSockets()) {
      const userId = this.state
        .getTags(socket)
        .find((tag) => tag.startsWith("user:"))
        ?.slice(5);
      if (!userId) continue;
      socket.send(
        JSON.stringify({
          op: 5,
          event: "VOICE_SUBSCRIPTIONS",
          data: {
            publishers: selectVoiceSubscriptions(candidates, userId, now, 8)
              .map((selectedId) => publishers.get(selectedId))
              .filter((publisher) => publisher?.session_id)
              .map((publisher) => ({
                userId: publisher!.user_id,
                sessionId: publisher!.session_id!,
                tracks: JSON.parse(
                  publisher!.published_tracks_json,
                ) as PublishedTrack[],
              })),
          },
        }),
      );
    }
  }

  private snapshot() {
    const participants = this.sql
      .exec<Record<string, string | number>>(
        "SELECT user_id, display_name, muted, deafened, camera, screen, speaking, joined_at FROM participants ORDER BY joined_at",
      )
      .toArray()
      .map((row) => ({
        userId: String(row.user_id),
        displayName: String(row.display_name),
        muted: Boolean(row.muted),
        deafened: Boolean(row.deafened),
        camera: Boolean(row.camera),
        screen: Boolean(row.screen),
        speaking: Boolean(row.speaking),
        joinedAt: String(row.joined_at),
      }));
    return {
      participants,
      limits: { participants: this.roomLimit, screenShares: this.screenLimit },
    };
  }
}

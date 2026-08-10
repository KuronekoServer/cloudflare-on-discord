import type { Env } from "../env";
import { broadcast, json, readJson, upgradeWebSocket } from "./shared";

interface StoredMessage {
  id: string;
  channelId: string;
  authorId: string;
  authorUsername: string;
  authorDisplayName: string;
  authorBot?: boolean;
  content: string;
  createdAt: string;
  replyToId: string | null;
  attachments: unknown[];
  partitionKey: string;
  poll?: {
    question: string;
    answers: string[];
    durationHours: number;
    allowMultiselect: boolean;
  };
  slowmodeSeconds: number;
  bypassSlowmode: boolean;
}

export class ChannelHubDO {
  private readonly sql: SqlStorage;

  constructor(
    private readonly state: DurableObjectState,
    private readonly env: Env,
  ) {
    this.sql = state.storage.sql;
    this.sql.exec(`CREATE TABLE IF NOT EXISTS messages (
      sequence INTEGER PRIMARY KEY AUTOINCREMENT,
      id TEXT NOT NULL UNIQUE,
      channel_id TEXT NOT NULL,
      author_id TEXT NOT NULL,
      author_username TEXT NOT NULL,
      author_display_name TEXT NOT NULL,
      author_bot INTEGER NOT NULL DEFAULT 0,
      content TEXT NOT NULL,
      created_at TEXT NOT NULL,
      edited_at TEXT,
      reply_to_id TEXT,
      pinned INTEGER NOT NULL DEFAULT 0,
      attachments_json TEXT NOT NULL DEFAULT '[]',
      deleted_at TEXT
    )`);
    this.sql.exec(
      "CREATE INDEX IF NOT EXISTS messages_history ON messages(sequence DESC)",
    );
    this.sql.exec(`CREATE TABLE IF NOT EXISTS event_outbox (
      event_id TEXT PRIMARY KEY,
      topic TEXT NOT NULL,
      partition_key TEXT NOT NULL,
      payload_json TEXT NOT NULL,
      created_at TEXT NOT NULL,
      delivered_at TEXT,
      attempts INTEGER NOT NULL DEFAULT 0
    )`);
    this.sql.exec(
      "CREATE INDEX IF NOT EXISTS event_outbox_pending ON event_outbox(delivered_at, created_at)",
    );
    this.sql.exec(`CREATE TABLE IF NOT EXISTS reactions (
      message_id TEXT NOT NULL,
      emoji TEXT NOT NULL,
      user_id TEXT NOT NULL,
      created_at TEXT NOT NULL,
      PRIMARY KEY(message_id, emoji, user_id)
    )`);
    this.sql.exec(`CREATE TABLE IF NOT EXISTS polls (
      message_id TEXT PRIMARY KEY,
      question TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      allow_multiselect INTEGER NOT NULL DEFAULT 0
    )`);
    this.sql.exec(`CREATE TABLE IF NOT EXISTS poll_answers (
      message_id TEXT NOT NULL,
      answer_id INTEGER NOT NULL,
      text TEXT NOT NULL,
      PRIMARY KEY(message_id, answer_id)
    )`);
    this.sql.exec(`CREATE TABLE IF NOT EXISTS poll_votes (
      message_id TEXT NOT NULL,
      answer_id INTEGER NOT NULL,
      user_id TEXT NOT NULL,
      created_at TEXT NOT NULL,
      PRIMARY KEY(message_id, answer_id, user_id)
    )`);
    this.sql.exec(`CREATE TABLE IF NOT EXISTS send_limits (
      user_id TEXT PRIMARY KEY,
      last_sent_at TEXT NOT NULL
    )`);
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (request.headers.get("upgrade")?.toLowerCase() === "websocket") {
      const userId = url.searchParams.get("user") ?? "anonymous";
      return upgradeWebSocket(this.state, request, [`user:${userId}`]);
    }

    if (url.pathname === "/account/messages" && request.method === "GET") {
      const userId = url.searchParams.get("user") ?? "";
      const after = Math.max(Number(url.searchParams.get("after") ?? 0), 0);
      const rows = this.sql
        .exec<Record<string, string | number | null>>(
          `SELECT sequence,id,channel_id,author_id,author_username,author_display_name,
                  author_bot,content,created_at,edited_at,reply_to_id,pinned,
                  attachments_json,deleted_at
             FROM messages WHERE author_id=? AND sequence>?
            ORDER BY sequence LIMIT 100`,
          userId,
          after,
        )
        .toArray();
      return json({
        messages: rows.map((row) => ({
          ...this.toMessage(row, userId),
          deletedAt: row.deleted_at === null ? null : String(row.deleted_at),
        })),
      });
    }
    if (url.pathname === "/account/messages" && request.method === "DELETE") {
      const input = await readJson<{
        userId: string;
        partitionKey: string;
      }>(request);
      const rows = this.sql
        .exec<Record<string, string | number | null>>(
          `SELECT sequence,id,channel_id,created_at FROM messages
            WHERE author_id=? AND deleted_at IS NULL ORDER BY sequence LIMIT 100`,
          input.userId,
        )
        .toArray();
      const deletedAt = new Date().toISOString();
      this.state.storage.transactionSync(() => {
        this.sql.exec("DELETE FROM reactions WHERE user_id=?", input.userId);
        this.sql.exec("DELETE FROM poll_votes WHERE user_id=?", input.userId);
        for (const row of rows) {
          this.sql.exec(
            `UPDATE messages
                SET author_id='deleted-user',author_username='deleted-user',
                    author_display_name='Deleted User',content='',attachments_json='[]',
                    deleted_at=? WHERE id=?`,
            deletedAt,
            String(row.id),
          );
          this.insertOutbox("search.delete", input.partitionKey, {
            messageId: String(row.id),
            month: String(row.created_at).slice(0, 7),
          });
          this.insertOutbox("message.archive", input.partitionKey, {
            message: {
              id: String(row.id),
              channelId: String(row.channel_id),
              sequence: String(row.sequence),
              createdAt: String(row.created_at),
              deletedAt,
            },
          });
        }
      });
      if (rows.length > 0) await this.state.storage.setAlarm(Date.now());
      for (const row of rows)
        broadcast(this.state, {
          op: 0,
          event: "MESSAGE_DELETE",
          data: {
            id: String(row.id),
            channelId: String(row.channel_id),
            deletedAt,
          },
        });
      const remaining = this.sql
        .exec<{ count: number }>(
          "SELECT count(*) AS count FROM messages WHERE author_id=? AND deleted_at IS NULL",
          input.userId,
        )
        .one().count;
      return json({ erased: rows.length, remaining });
    }

    const messageMatch = url.pathname.match(/^\/messages\/([^/]+)$/);
    if (messageMatch && request.method === "GET") {
      const row = this.messageRow(messageMatch[1]!, true);
      if (!row) return json({ code: "MESSAGE_NOT_FOUND" }, { status: 404 });
      return json(this.toMessage(row, url.searchParams.get("viewer") ?? ""));
    }
    if (messageMatch && request.method === "PATCH")
      return this.updateMessage(messageMatch[1]!, request);
    if (messageMatch && request.method === "DELETE")
      return this.deleteMessage(messageMatch[1]!, request);
    const reactionMatch = url.pathname.match(
      /^\/messages\/([^/]+)\/reactions\/([^/]+)$/,
    );
    if (reactionMatch && ["PUT", "DELETE"].includes(request.method))
      return this.updateReaction(
        reactionMatch[1]!,
        decodeURIComponent(reactionMatch[2]!),
        request,
      );
    const pinMatch = url.pathname.match(/^\/pins\/([^/]+)$/);
    if (pinMatch && ["PUT", "DELETE"].includes(request.method))
      return this.updatePin(pinMatch[1]!, request);
    if (url.pathname === "/pins" && request.method === "GET") {
      const viewerId = url.searchParams.get("viewer") ?? "";
      const rows = this.sql
        .exec<Record<string, string | number | null>>(
          `SELECT sequence,id,channel_id,author_id,author_username,author_display_name,
                  author_bot,content,created_at,edited_at,reply_to_id,pinned,attachments_json
             FROM messages WHERE pinned=1 AND deleted_at IS NULL
            ORDER BY sequence DESC LIMIT 50`,
        )
        .toArray();
      return json(rows.map((row) => this.toMessage(row, viewerId)));
    }
    const voteMatch = url.pathname.match(/^\/polls\/([^/]+)\/answers\/(\d+)$/);
    if (voteMatch && ["PUT", "DELETE"].includes(request.method))
      return this.updatePollVote(voteMatch[1]!, Number(voteMatch[2]), request);

    if (request.method === "GET") {
      const before = Number(
        url.searchParams.get("beforeSequence") ?? Number.MAX_SAFE_INTEGER,
      );
      const limit = Math.min(
        Math.max(Number(url.searchParams.get("limit") ?? 50), 1),
        100,
      );
      const rows = this.sql
        .exec<Record<string, string | number | null>>(
          `SELECT sequence, id, channel_id, author_id, author_username, author_display_name,
                  author_bot, content, created_at, edited_at, reply_to_id, pinned, attachments_json
             FROM messages
            WHERE sequence < ? AND deleted_at IS NULL
            ORDER BY sequence DESC LIMIT ?`,
          before,
          limit,
        )
        .toArray();
      const viewerId = url.searchParams.get("viewer") ?? "";
      return json({
        messages: rows.map((row) => this.toMessage(row, viewerId)).reverse(),
      });
    }

    if (request.method === "POST") {
      const message = await readJson<StoredMessage>(request);
      if (message.slowmodeSeconds > 0 && !message.bypassSlowmode) {
        const limit = this.sql
          .exec<{ last_sent_at: string }>(
            "SELECT last_sent_at FROM send_limits WHERE user_id=?",
            message.authorId,
          )
          .toArray()[0];
        const retryAfter = limit
          ? message.slowmodeSeconds * 1000 -
            (Date.now() - Date.parse(limit.last_sent_at))
          : 0;
        if (retryAfter > 0)
          return json(
            { code: "SLOWMODE", retryAfterMs: retryAfter },
            { status: 429 },
          );
      }
      let row!: Record<string, string | number | null>;
      this.state.storage.transactionSync(() => {
        this.sql.exec(
          `INSERT INTO messages(id, channel_id, author_id, author_username, author_display_name, author_bot, content, created_at, reply_to_id, attachments_json)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          message.id,
          message.channelId,
          message.authorId,
          message.authorUsername,
          message.authorDisplayName,
          Number(message.authorBot ?? false),
          message.content,
          message.createdAt,
          message.replyToId,
          JSON.stringify(message.attachments),
        );
        this.sql.exec(
          `INSERT INTO send_limits(user_id,last_sent_at) VALUES (?,?)
           ON CONFLICT(user_id) DO UPDATE SET last_sent_at=excluded.last_sent_at`,
          message.authorId,
          message.createdAt,
        );
        row = this.sql
          .exec<Record<string, string | number | null>>(
            `SELECT sequence, id, channel_id, author_id, author_username, author_display_name,
                    author_bot, content, created_at, edited_at, reply_to_id, pinned, attachments_json
               FROM messages WHERE id = ?`,
            message.id,
          )
          .one();
        if (message.poll) {
          this.sql.exec(
            "INSERT INTO polls(message_id,question,expires_at,allow_multiselect) VALUES (?,?,?,?)",
            message.id,
            message.poll.question,
            new Date(
              Date.parse(message.createdAt) +
                message.poll.durationHours * 60 * 60 * 1000,
            ).toISOString(),
            Number(message.poll.allowMultiselect),
          );
          for (const [index, answer] of message.poll.answers.entries())
            this.sql.exec(
              "INSERT INTO poll_answers(message_id,answer_id,text) VALUES (?,?,?)",
              message.id,
              index + 1,
              answer,
            );
        }
        const result = this.toMessage(row, message.authorId);
        this.insertOutbox("search.index", message.partitionKey, {
          messageId: message.id,
          channelId: message.channelId,
          content: message.content,
          authorName: message.authorDisplayName,
        });
        this.insertOutbox("message.archive", message.partitionKey, {
          message: result,
        });
        this.insertOutbox("bot.dispatch", message.partitionKey, {
          event: "MESSAGE_CREATE",
          data: result,
          guildId: message.partitionKey.startsWith("dm:")
            ? null
            : message.partitionKey,
          requiredIntent: message.partitionKey.startsWith("dm:")
            ? "4096"
            : "512",
        });
      });
      await this.state.storage.setAlarm(Date.now());
      const result = this.toMessage(row, message.authorId);
      broadcast(this.state, {
        op: 0,
        event: "MESSAGE_CREATE",
        sequence: String(row.sequence),
        data: result,
      });
      return json(result, { status: 201 });
    }
    return new Response("Method not allowed", { status: 405 });
  }

  async alarm(): Promise<void> {
    const pending = this.sql
      .exec<{
        event_id: string;
        topic:
          "search.index" | "search.delete" | "message.archive" | "bot.dispatch";
        partition_key: string;
        payload_json: string;
      }>(
        `SELECT event_id,topic,partition_key,payload_json
           FROM event_outbox WHERE delivered_at IS NULL
           ORDER BY created_at LIMIT 50`,
      )
      .toArray();
    for (const event of pending) {
      await this.env.EVENT_QUEUE.send({
        id: event.event_id,
        topic: event.topic,
        partitionKey: event.partition_key,
        payload: JSON.parse(event.payload_json) as Record<string, unknown>,
      });
      this.sql.exec(
        "UPDATE event_outbox SET delivered_at=?,attempts=attempts+1 WHERE event_id=?",
        new Date().toISOString(),
        event.event_id,
      );
    }
    const remaining = this.sql
      .exec<{ count: number }>(
        "SELECT count(*) AS count FROM event_outbox WHERE delivered_at IS NULL",
      )
      .one();
    if (remaining.count > 0) await this.state.storage.setAlarm(Date.now());
  }

  private async updateMessage(id: string, request: Request): Promise<Response> {
    const input = await readJson<{
      actorId: string;
      canManage: boolean;
      content: string;
      partitionKey: string;
    }>(request);
    if (typeof input.content !== "string" || input.content.length > 4000)
      return json({ code: "VALIDATION_ERROR" }, { status: 400 });
    const existing = this.messageRow(id, true);
    if (!existing) return json({ code: "MESSAGE_NOT_FOUND" }, { status: 404 });
    if (String(existing.author_id) !== input.actorId && !input.canManage)
      return json({ code: "MISSING_PERMISSIONS" }, { status: 403 });
    let row!: Record<string, string | number | null>;
    this.state.storage.transactionSync(() => {
      this.sql.exec(
        "UPDATE messages SET content=?,edited_at=? WHERE id=? AND deleted_at IS NULL",
        input.content,
        new Date().toISOString(),
        id,
      );
      row = this.messageRow(id, true)!;
      const updated = this.toMessage(row, input.actorId);
      this.insertOutbox("search.index", input.partitionKey, {
        messageId: id,
        channelId: String(row.channel_id),
        content: input.content,
        authorName: String(row.author_display_name),
        month: String(row.created_at).slice(0, 7),
      });
      this.insertOutbox("message.archive", input.partitionKey, {
        message: updated,
      });
      this.insertOutbox("bot.dispatch", input.partitionKey, {
        event: "MESSAGE_UPDATE",
        data: updated,
        guildId: input.partitionKey.startsWith("dm:")
          ? null
          : input.partitionKey,
        requiredIntent: input.partitionKey.startsWith("dm:") ? "4096" : "512",
      });
    });
    await this.state.storage.setAlarm(Date.now());
    const result = this.toMessage(row, input.actorId);
    broadcast(this.state, { op: 0, event: "MESSAGE_UPDATE", data: result });
    return json(result);
  }

  private async deleteMessage(id: string, request: Request): Promise<Response> {
    const input = await readJson<{
      actorId: string;
      canManage: boolean;
      partitionKey: string;
    }>(request);
    const existing = this.messageRow(id, true);
    if (!existing) return json({ code: "MESSAGE_NOT_FOUND" }, { status: 404 });
    if (String(existing.author_id) !== input.actorId && !input.canManage)
      return json({ code: "MISSING_PERMISSIONS" }, { status: 403 });
    const deletedAt = new Date().toISOString();
    this.state.storage.transactionSync(() => {
      this.sql.exec(
        "UPDATE messages SET content='',attachments_json='[]',deleted_at=? WHERE id=? AND deleted_at IS NULL",
        deletedAt,
        id,
      );
      this.sql.exec("DELETE FROM reactions WHERE message_id=?", id);
      this.sql.exec("DELETE FROM poll_votes WHERE message_id=?", id);
      this.insertOutbox("search.delete", input.partitionKey, {
        messageId: id,
        month: String(existing.created_at).slice(0, 7),
      });
      this.insertOutbox("message.archive", input.partitionKey, {
        message: {
          id,
          channelId: String(existing.channel_id),
          sequence: String(existing.sequence),
          createdAt: String(existing.created_at),
          deletedAt,
        },
      });
      this.insertOutbox("bot.dispatch", input.partitionKey, {
        event: "MESSAGE_DELETE",
        data: { id, channelId: String(existing.channel_id) },
        guildId: input.partitionKey.startsWith("dm:")
          ? null
          : input.partitionKey,
        requiredIntent: input.partitionKey.startsWith("dm:") ? "4096" : "512",
      });
    });
    await this.state.storage.setAlarm(Date.now());
    broadcast(this.state, {
      op: 0,
      event: "MESSAGE_DELETE",
      data: { id, channelId: String(existing.channel_id), deletedAt },
    });
    return new Response(null, { status: 204 });
  }

  private async updateReaction(
    messageId: string,
    emoji: string,
    request: Request,
  ): Promise<Response> {
    const input = await readJson<{
      actorId: string;
      partitionKey?: string;
    }>(request);
    if (!input.actorId || emoji.length < 1 || emoji.length > 128)
      return json({ code: "VALIDATION_ERROR" }, { status: 400 });
    if (!this.messageRow(messageId, true))
      return json({ code: "MESSAGE_NOT_FOUND" }, { status: 404 });
    if (request.method === "PUT")
      this.sql.exec(
        "INSERT OR IGNORE INTO reactions(message_id,emoji,user_id,created_at) VALUES (?,?,?,?)",
        messageId,
        emoji,
        input.actorId,
        new Date().toISOString(),
      );
    else
      this.sql.exec(
        "DELETE FROM reactions WHERE message_id=? AND emoji=? AND user_id=?",
        messageId,
        emoji,
        input.actorId,
      );
    const data = { messageId, emoji, userId: input.actorId };
    if (input.partitionKey) {
      this.insertOutbox("bot.dispatch", input.partitionKey, {
        event:
          request.method === "PUT"
            ? "MESSAGE_REACTION_ADD"
            : "MESSAGE_REACTION_REMOVE",
        data: {
          userId: input.actorId,
          channelId: String(this.messageRow(messageId, true)!.channel_id),
          messageId,
          emoji: { id: null, name: emoji },
        },
        guildId: input.partitionKey.startsWith("dm:")
          ? null
          : input.partitionKey,
        requiredIntent: input.partitionKey.startsWith("dm:") ? "8192" : "1024",
      });
      await this.state.storage.setAlarm(Date.now());
    }
    broadcast(this.state, {
      op: 0,
      event:
        request.method === "PUT"
          ? "MESSAGE_REACTION_ADD"
          : "MESSAGE_REACTION_REMOVE",
      data,
    });
    return json(data);
  }

  private async updatePin(
    messageId: string,
    request: Request,
  ): Promise<Response> {
    const input = await readJson<{
      canManage: boolean;
      partitionKey?: string;
    }>(request);
    if (!input.canManage)
      return json({ code: "MISSING_PERMISSIONS" }, { status: 403 });
    if (!this.messageRow(messageId, true))
      return json({ code: "MESSAGE_NOT_FOUND" }, { status: 404 });
    const pinned = request.method === "PUT";
    this.sql.exec(
      "UPDATE messages SET pinned=? WHERE id=?",
      Number(pinned),
      messageId,
    );
    const row = this.messageRow(messageId, true)!;
    if (input.partitionKey) {
      this.insertOutbox("bot.dispatch", input.partitionKey, {
        event: "CHANNEL_PINS_UPDATE",
        data: {
          guildId: input.partitionKey.startsWith("dm:")
            ? null
            : input.partitionKey,
          channelId: String(row.channel_id),
          lastPinTimestamp: pinned ? new Date().toISOString() : null,
        },
        guildId: input.partitionKey.startsWith("dm:")
          ? null
          : input.partitionKey,
        requiredIntent: input.partitionKey.startsWith("dm:") ? "4096" : "512",
      });
      await this.state.storage.setAlarm(Date.now());
    }
    broadcast(this.state, {
      op: 0,
      event: "CHANNEL_PINS_UPDATE",
      data: { messageId, pinned },
    });
    return new Response(null, { status: 204 });
  }

  private async updatePollVote(
    messageId: string,
    answerId: number,
    request: Request,
  ): Promise<Response> {
    const input = await readJson<{ actorId: string }>(request);
    const poll = this.sql
      .exec<{ expires_at: string; allow_multiselect: number }>(
        `SELECT p.expires_at,p.allow_multiselect FROM polls p
          JOIN poll_answers a ON a.message_id=p.message_id
         WHERE p.message_id=? AND a.answer_id=?`,
        messageId,
        answerId,
      )
      .toArray()[0];
    if (!poll) return json({ code: "POLL_NOT_FOUND" }, { status: 404 });
    if (Date.parse(poll.expires_at) <= Date.now())
      return json({ code: "POLL_EXPIRED" }, { status: 409 });
    this.state.storage.transactionSync(() => {
      if (request.method === "PUT") {
        if (!poll.allow_multiselect)
          this.sql.exec(
            "DELETE FROM poll_votes WHERE message_id=? AND user_id=?",
            messageId,
            input.actorId,
          );
        this.sql.exec(
          "INSERT OR IGNORE INTO poll_votes(message_id,answer_id,user_id,created_at) VALUES (?,?,?,?)",
          messageId,
          answerId,
          input.actorId,
          new Date().toISOString(),
        );
      } else {
        this.sql.exec(
          "DELETE FROM poll_votes WHERE message_id=? AND answer_id=? AND user_id=?",
          messageId,
          answerId,
          input.actorId,
        );
      }
    });
    const row = this.messageRow(messageId, true)!;
    const result = this.toMessage(row, input.actorId);
    broadcast(this.state, { op: 0, event: "MESSAGE_UPDATE", data: result });
    return json(result.poll);
  }

  private messageRow(
    id: string,
    activeOnly: boolean,
  ): Record<string, string | number | null> | null {
    return (
      this.sql
        .exec<Record<string, string | number | null>>(
          `SELECT sequence,id,channel_id,author_id,author_username,author_display_name,
                  author_bot,content,created_at,edited_at,reply_to_id,pinned,attachments_json
             FROM messages WHERE id=? ${activeOnly ? "AND deleted_at IS NULL" : ""}`,
          id,
        )
        .toArray()[0] ?? null
    );
  }

  webSocketMessage(socket: WebSocket, message: string | ArrayBuffer): void {
    if (typeof message !== "string") return;
    try {
      const payload = JSON.parse(message) as { op?: number; data?: unknown };
      if (payload.op === 1)
        socket.send(JSON.stringify({ op: 2, data: { at: Date.now() } }));
      if (payload.op === 4)
        broadcast(
          this.state,
          { op: 4, event: "TYPING", data: payload.data },
          socket,
        );
    } catch {
      socket.send(
        JSON.stringify({ op: 9, data: { message: "Invalid gateway payload" } }),
      );
    }
  }

  webSocketClose(socket: WebSocket, code: number, reason: string): void {
    socket.close(code, reason);
  }

  private insertOutbox(
    topic:
      "search.index" | "search.delete" | "message.archive" | "bot.dispatch",
    partitionKey: string,
    payload: Record<string, unknown>,
  ): void {
    this.sql.exec(
      `INSERT INTO event_outbox(event_id,topic,partition_key,payload_json,created_at)
       VALUES (?,?,?,?,?)`,
      crypto.randomUUID(),
      topic,
      partitionKey,
      JSON.stringify(payload),
      new Date().toISOString(),
    );
  }

  private toMessage(
    row: Record<string, string | number | null>,
    viewerId: string,
  ) {
    const message = toMessage(row);
    const reactions = this.sql
      .exec<{ emoji: string; count: number; me: number }>(
        `SELECT emoji,count(*) AS count,
                max(CASE WHEN user_id=? THEN 1 ELSE 0 END) AS me
           FROM reactions WHERE message_id=? GROUP BY emoji ORDER BY emoji`,
        viewerId,
        message.id,
      )
      .toArray()
      .map((reaction) => ({
        emoji: reaction.emoji,
        count: reaction.count,
        me: Boolean(reaction.me),
      }));
    const poll = this.sql
      .exec<{
        question: string;
        expires_at: string;
        allow_multiselect: number;
      }>(
        "SELECT question,expires_at,allow_multiselect FROM polls WHERE message_id=?",
        message.id,
      )
      .toArray()[0];
    const answers = poll
      ? this.sql
          .exec<{
            answer_id: number;
            text: string;
            vote_count: number;
            me_voted: number;
          }>(
            `SELECT a.answer_id,a.text,count(v.user_id) AS vote_count,
                    max(CASE WHEN v.user_id=? THEN 1 ELSE 0 END) AS me_voted
               FROM poll_answers a
               LEFT JOIN poll_votes v ON v.message_id=a.message_id AND v.answer_id=a.answer_id
              WHERE a.message_id=? GROUP BY a.answer_id,a.text ORDER BY a.answer_id`,
            viewerId,
            message.id,
          )
          .toArray()
          .map((answer) => ({
            id: String(answer.answer_id),
            text: answer.text,
            voteCount: answer.vote_count,
            meVoted: Boolean(answer.me_voted),
          }))
      : [];
    return {
      ...message,
      reactions,
      poll: poll
        ? {
            question: poll.question,
            expiresAt: poll.expires_at,
            allowMultiselect: Boolean(poll.allow_multiselect),
            answers,
          }
        : null,
    };
  }
}

function toMessage(row: Record<string, string | number | null>) {
  return {
    id: String(row.id),
    channelId: String(row.channel_id),
    author: {
      id: String(row.author_id),
      username: String(row.author_username),
      displayName: String(row.author_display_name),
      avatarUrl: null,
      bot: Boolean(row.author_bot),
      status: "online",
    },
    content: String(row.content),
    sequence: String(row.sequence),
    createdAt: String(row.created_at),
    editedAt: row.edited_at === null ? null : String(row.edited_at),
    replyToId: row.reply_to_id === null ? null : String(row.reply_to_id),
    attachments: JSON.parse(String(row.attachments_json ?? "[]")),
    pinned: Boolean(row.pinned),
  };
}

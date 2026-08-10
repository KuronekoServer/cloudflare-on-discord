import type { Env } from "../env";
import { json, readJson } from "./shared";

export class MessagePartitionDO {
  private readonly sql: SqlStorage;

  constructor(state: DurableObjectState, _env: Env) {
    this.sql = state.storage.sql;
    this.sql.exec(
      "CREATE TABLE IF NOT EXISTS archive (id TEXT PRIMARY KEY, channel_id TEXT NOT NULL, sequence TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT NOT NULL)",
    );
    this.sql.exec(
      "CREATE INDEX IF NOT EXISTS archive_channel ON archive(channel_id, sequence)",
    );
  }

  async fetch(request: Request): Promise<Response> {
    if (request.method === "PUT") {
      const item = await readJson<{
        id: string;
        channelId: string;
        sequence: string;
        payload: unknown;
        createdAt: string;
      }>(request);
      this.sql.exec(
        "INSERT OR REPLACE INTO archive(id, channel_id, sequence, payload, created_at) VALUES (?, ?, ?, ?, ?)",
        item.id,
        item.channelId,
        item.sequence,
        JSON.stringify(item.payload),
        item.createdAt,
      );
      return new Response(null, { status: 204 });
    }
    const channelId = new URL(request.url).searchParams.get("channelId") ?? "";
    const rows = this.sql
      .exec<{ payload: string }>(
        "SELECT payload FROM archive WHERE channel_id = ? ORDER BY CAST(sequence AS INTEGER) DESC LIMIT 100",
        channelId,
      )
      .toArray();
    return json({ messages: rows.map((row) => JSON.parse(row.payload)) });
  }
}

export class GuildSearchPartitionDO {
  private readonly sql: SqlStorage;

  constructor(state: DurableObjectState, _env: Env) {
    this.sql = state.storage.sql;
    this.sql.exec(
      "CREATE VIRTUAL TABLE IF NOT EXISTS message_search USING fts5(message_id UNINDEXED, channel_id UNINDEXED, content, author_name)",
    );
  }

  async fetch(request: Request): Promise<Response> {
    if (request.method === "PUT") {
      const item = await readJson<{
        messageId: string;
        channelId: string;
        content: string;
        authorName: string;
      }>(request);
      this.sql.exec(
        "DELETE FROM message_search WHERE message_id = ?",
        item.messageId,
      );
      this.sql.exec(
        "INSERT INTO message_search(message_id, channel_id, content, author_name) VALUES (?, ?, ?, ?)",
        item.messageId,
        item.channelId,
        item.content,
        item.authorName,
      );
      return new Response(null, { status: 204 });
    }
    if (request.method === "DELETE") {
      const id = new URL(request.url).searchParams.get("messageId") ?? "";
      this.sql.exec("DELETE FROM message_search WHERE message_id = ?", id);
      return new Response(null, { status: 204 });
    }
    const query = new URL(request.url).searchParams.get("q")?.trim() ?? "";
    if (!query) return json({ messages: [] });
    const literalQuery = `"${query.replaceAll('"', '""')}"`;
    const rows = this.sql
      .exec<{
        message_id: string;
        channel_id: string;
        excerpt: string;
      }>(
        "SELECT message_id, channel_id, snippet(message_search, 2, '<mark>', '</mark>', '…', 16) AS excerpt FROM message_search WHERE message_search MATCH ? LIMIT 50",
        literalQuery,
      )
      .toArray();
    return json({ messages: rows });
  }
}

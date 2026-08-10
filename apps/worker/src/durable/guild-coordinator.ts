import type { Env } from "../env";
import { json, readJson } from "./shared";

export class GuildCoordinatorDO {
  private readonly sql: SqlStorage;

  constructor(
    private readonly state: DurableObjectState,
    _env: Env,
  ) {
    this.sql = state.storage.sql;
    this.sql.exec(
      "CREATE TABLE IF NOT EXISTS revision (singleton INTEGER PRIMARY KEY CHECK(singleton = 1), value INTEGER NOT NULL)",
    );
    this.sql.exec(
      "INSERT OR IGNORE INTO revision(singleton, value) VALUES (1, 0)",
    );
    this.sql.exec(
      "CREATE TABLE IF NOT EXISTS changes (revision INTEGER PRIMARY KEY, kind TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT NOT NULL)",
    );
  }

  async fetch(request: Request): Promise<Response> {
    if (request.method === "GET") {
      const revision = this.sql
        .exec<{ value: number }>(
          "SELECT value FROM revision WHERE singleton = 1",
        )
        .one().value;
      return json({ revision: String(revision) });
    }
    if (request.method === "POST") {
      const change = await readJson<{ kind: string; payload: unknown }>(
        request,
      );
      this.sql.exec(
        "UPDATE revision SET value = value + 1 WHERE singleton = 1",
      );
      const revision = this.sql
        .exec<{ value: number }>(
          "SELECT value FROM revision WHERE singleton = 1",
        )
        .one().value;
      this.sql.exec(
        "INSERT INTO changes(revision, kind, payload, created_at) VALUES (?, ?, ?, ?)",
        revision,
        change.kind,
        JSON.stringify(change.payload),
        new Date().toISOString(),
      );
      return json({ revision: String(revision) }, { status: 201 });
    }
    return new Response("Method not allowed", { status: 405 });
  }
}

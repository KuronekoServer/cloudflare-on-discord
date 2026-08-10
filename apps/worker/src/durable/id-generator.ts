import { composeSnowflake } from "@cloudcord/core";
import type { Env } from "../env";
import { json } from "./shared";

export class IdGeneratorDO {
  private readonly sql: SqlStorage;

  constructor(
    private readonly state: DurableObjectState,
    _env: Env,
  ) {
    this.sql = state.storage.sql;
    this.sql.exec(
      "CREATE TABLE IF NOT EXISTS generator_state (singleton INTEGER PRIMARY KEY CHECK(singleton = 1), last_ms INTEGER NOT NULL, sequence INTEGER NOT NULL)",
    );
    this.sql.exec(
      "INSERT OR IGNORE INTO generator_state(singleton, last_ms, sequence) VALUES (1, 0, 0)",
    );
  }

  fetch(request: Request): Response {
    if (request.method !== "POST")
      return new Response("Method not allowed", { status: 405 });
    const workerId = Number(
      new URL(request.url).searchParams.get("worker") ?? "0",
    );
    let timestamp = Date.now();
    const current = this.sql
      .exec<{ last_ms: number; sequence: number }>(
        "SELECT last_ms, sequence FROM generator_state WHERE singleton = 1",
      )
      .one();
    if (timestamp < current.last_ms) timestamp = current.last_ms;
    let sequence = timestamp === current.last_ms ? current.sequence + 1 : 0;
    if (sequence > 4095) {
      timestamp = current.last_ms + 1;
      sequence = 0;
    }
    this.sql.exec(
      "UPDATE generator_state SET last_ms = ?, sequence = ? WHERE singleton = 1",
      timestamp,
      sequence,
    );
    return json({
      id: composeSnowflake(timestamp, workerId, sequence),
      timestamp,
      sequence: String(sequence),
    });
  }
}

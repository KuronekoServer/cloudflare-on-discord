import { shardFor } from "@cloudcord/core";
import { WorkflowEntrypoint } from "cloudflare:workers";
import type { WorkflowEvent, WorkflowStep } from "cloudflare:workers";
import { databaseBinding } from "../shard-router";
import type { Env } from "../env";

export interface ShardMigrationParams {
  runId: string;
  domain: "social" | "guild";
  bucket: number;
  generation: number;
  sourceBinding: string;
  targetBinding: string;
}

export class ShardMigrationWorkflow extends WorkflowEntrypoint<
  Env,
  ShardMigrationParams
> {
  async run(
    event: WorkflowEvent<ShardMigrationParams>,
    step: WorkflowStep,
  ): Promise<{ copiedRows: number; generation: number }> {
    const params = event.payload;
    try {
      return await this.migrate(params, step);
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : String(cause);
      await step.do("restore source after failure", async () => {
        const timestamp = new Date().toISOString();
        await this.env.IDENTITY_DB.batch([
          this.env.IDENTITY_DB.prepare(
            `UPDATE shard_map SET state='retired',updated_at=?1
              WHERE domain=?2 AND bucket=?3 AND generation=?4
                AND state IN ('dual_write','cutover')`,
          ).bind(timestamp, params.domain, params.bucket, params.generation),
          this.env.IDENTITY_DB.prepare(
            `UPDATE shard_migration_runs
                SET phase='errored',error=?1,updated_at=?2 WHERE id=?3`,
          ).bind(message.slice(0, 2048), timestamp, params.runId),
        ]);
      });
      throw cause;
    }
  }

  private async migrate(
    params: ShardMigrationParams,
    step: WorkflowStep,
  ): Promise<{ copiedRows: number; generation: number }> {
    await step.do("enable dual write", async () => {
      validateBindings(this.env, params);
      const current = await this.env.IDENTITY_DB.prepare(
        `SELECT generation,binding_name,state FROM shard_map
          WHERE domain=?1 AND bucket=?2
          ORDER BY generation DESC LIMIT 1`,
      )
        .bind(params.domain, params.bucket)
        .first<{ generation: number; binding_name: string; state: string }>();
      if (
        !current ||
        current.generation !== params.generation - 1 ||
        current.binding_name !== params.sourceBinding ||
        current.state !== "active"
      )
        throw new Error("Shard mapping changed before migration started");
      await this.env.IDENTITY_DB.batch([
        this.env.IDENTITY_DB.prepare(
          `INSERT INTO shard_map(domain,bucket,generation,binding_name,read_binding_name,state,updated_at)
           VALUES (?1,?2,?3,?4,?5,'dual_write',?6)`,
        ).bind(
          params.domain,
          params.bucket,
          params.generation,
          params.sourceBinding,
          params.targetBinding,
          new Date().toISOString(),
        ),
        this.env.IDENTITY_DB.prepare(
          "UPDATE shard_migration_runs SET phase='dual_write',updated_at=?1 WHERE id=?2",
        ).bind(new Date().toISOString(), params.runId),
      ]);
    });

    const initialRows = await step.do(
      "initial copy",
      { retries: { limit: 5, delay: "5 seconds", backoff: "exponential" } },
      async () => {
        const copied = await copyShard(this.env, params);
        await updateRun(this.env, params.runId, "initial_copy", copied);
        return copied;
      },
    );

    await step.do("enter cutover", async () => {
      const updated = await this.env.IDENTITY_DB.prepare(
        `UPDATE shard_map SET state='cutover',updated_at=?1
          WHERE domain=?2 AND bucket=?3 AND generation=?4 AND state='dual_write'`,
      )
        .bind(
          new Date().toISOString(),
          params.domain,
          params.bucket,
          params.generation,
        )
        .run();
      if (updated.meta.changes !== 1)
        throw new Error("Unable to enter shard cutover");
      await updateRun(this.env, params.runId, "cutover", initialRows);
    });

    await step.sleep("drain in-flight writes", "15 seconds");

    const finalRows = await step.do(
      "final reconciliation",
      { retries: { limit: 5, delay: "5 seconds", backoff: "exponential" } },
      async () => {
        const copied = await copyShard(this.env, params);
        await updateRun(
          this.env,
          params.runId,
          "reconciliation",
          initialRows + copied,
        );
        return copied;
      },
    );

    await step.do("activate target", async () => {
      const timestamp = new Date().toISOString();
      await this.env.IDENTITY_DB.batch([
        this.env.IDENTITY_DB.prepare(
          `UPDATE shard_map
              SET binding_name=?1,read_binding_name=?2,state='active',updated_at=?3
            WHERE domain=?4 AND bucket=?5 AND generation=?6 AND state='cutover'`,
        ).bind(
          params.targetBinding,
          params.sourceBinding,
          timestamp,
          params.domain,
          params.bucket,
          params.generation,
        ),
        this.env.IDENTITY_DB.prepare(
          `UPDATE shard_map SET state='retired',updated_at=?1
            WHERE domain=?2 AND bucket=?3 AND generation<?4`,
        ).bind(timestamp, params.domain, params.bucket, params.generation),
        this.env.IDENTITY_DB.prepare(
          `UPDATE shard_migration_runs
              SET phase='complete',copied_rows=?1,updated_at=?2
            WHERE id=?3`,
        ).bind(initialRows + finalRows, timestamp, params.runId),
      ]);
    });

    return {
      copiedRows: initialRows + finalRows,
      generation: params.generation,
    };
  }
}

function validateBindings(env: Env, params: ShardMigrationParams): void {
  if (params.sourceBinding === params.targetBinding)
    throw new Error("Source and target shard bindings must differ");
  const prefix = params.domain === "social" ? "SOCIAL_DB_" : "GUILD_DB_";
  if (
    !params.sourceBinding.startsWith(prefix) ||
    !params.targetBinding.startsWith(prefix)
  )
    throw new Error("Shard binding does not match its domain");
  databaseBinding(env, params.sourceBinding);
  databaseBinding(env, params.targetBinding);
}

async function updateRun(
  env: Env,
  runId: string,
  phase: string,
  copiedRows: number,
): Promise<void> {
  await env.IDENTITY_DB.prepare(
    `UPDATE shard_migration_runs
        SET phase=?1,copied_rows=?2,updated_at=?3 WHERE id=?4`,
  )
    .bind(phase, copiedRows, new Date().toISOString(), runId)
    .run();
}

async function copyShard(
  env: Env,
  params: ShardMigrationParams,
): Promise<number> {
  const source = databaseBinding(env, params.sourceBinding);
  const target = databaseBinding(env, params.targetBinding);
  return params.domain === "social"
    ? copySocialShard(source, target, params.bucket)
    : copyGuildShard(source, target, params.bucket);
}

async function copySocialShard(
  source: D1Database,
  target: D1Database,
  bucket: number,
): Promise<number> {
  let copied = 0;
  const userIds = new Set<string>();
  for (const query of [
    "SELECT DISTINCT user_id AS id FROM relationships",
    "SELECT DISTINCT user_id AS id FROM guild_membership_index",
    "SELECT DISTINCT user_id AS id FROM conversation_membership_index",
  ]) {
    const rows = await source.prepare(query).all<{ id: string }>();
    for (const row of rows.results)
      if (shardFor(row.id, 16) === bucket) userIds.add(row.id);
  }
  for (const userId of userIds) {
    copied += await copyRows(source, target, "relationships", "user_id=?1", [
      userId,
    ]);
    copied += await copyRows(
      source,
      target,
      "guild_membership_index",
      "user_id=?1",
      [userId],
    );
    copied += await copyRows(
      source,
      target,
      "conversation_membership_index",
      "user_id=?1",
      [userId],
    );
  }
  const conversations = await source
    .prepare("SELECT id FROM conversations")
    .all<{ id: string }>();
  for (const conversation of conversations.results) {
    if (shardFor(conversation.id, 16) !== bucket) continue;
    copied += await copyRows(source, target, "conversations", "id=?1", [
      conversation.id,
    ]);
    copied += await copyRows(
      source,
      target,
      "conversation_members",
      "conversation_id=?1",
      [conversation.id],
    );
  }
  return copied;
}

async function copyGuildShard(
  source: D1Database,
  target: D1Database,
  bucket: number,
): Promise<number> {
  let copied = 0;
  const guilds = await source
    .prepare("SELECT id FROM guilds")
    .all<{ id: string }>();
  const directTables = [
    "guilds",
    "roles",
    "members",
    "channels",
    "invites",
    "scheduled_events",
    "guild_audit",
    "reports",
    "bans",
    "automod_rules",
    "guild_emojis",
    "guild_stickers",
    "soundboard_sounds",
  ];
  for (const guild of guilds.results) {
    if (shardFor(guild.id, 32) !== bucket) continue;
    for (const table of directTables)
      copied += await copyRows(
        source,
        target,
        table,
        `${table === "guilds" ? "id" : "guild_id"}=?1`,
        [guild.id],
      );
    const channels = await source
      .prepare("SELECT id FROM channels WHERE guild_id=?1")
      .bind(guild.id)
      .all<{ id: string }>();
    for (const channel of channels.results) {
      for (const table of [
        "permission_overwrites",
        "thread_metadata",
        "forum_tags",
        "forum_post_tags",
      ])
        copied += await copyRows(source, target, table, "channel_id=?1", [
          channel.id,
        ]);
    }
  }
  return copied;
}

async function copyRows(
  source: D1Database,
  target: D1Database,
  table: string,
  where: string,
  values: unknown[],
): Promise<number> {
  let copied = 0;
  let offset = 0;
  while (true) {
    const page = await source
      .prepare(
        `SELECT * FROM ${table} WHERE ${where} LIMIT 100 OFFSET ${offset}`,
      )
      .bind(...values)
      .all<Record<string, unknown>>();
    if (page.results.length === 0) break;
    for (let start = 0; start < page.results.length; start += 50) {
      const rows = page.results.slice(start, start + 50);
      await target.batch(
        rows.map((row) => {
          const columns = Object.keys(row);
          const placeholders = columns.map((_, index) => `?${index + 1}`);
          return target
            .prepare(
              `INSERT INTO ${table} (${columns.join(",")}) VALUES (${placeholders.join(",")})
               ON CONFLICT DO UPDATE SET ${columns
                 .map((column) => `${column}=excluded.${column}`)
                 .join(",")}`,
            )
            .bind(...columns.map((column) => row[column]));
        }),
      );
    }
    copied += page.results.length;
    offset += page.results.length;
    if (page.results.length < 100) break;
  }
  return copied;
}

import { shardFor } from "@cloudcord/core";
import type { Env } from "./env";

export interface ShardResolution {
  domain: "social" | "guild";
  bucket: number;
  generation: number;
  primaryBinding: string;
  dualReadBinding: string | null;
  state: "active" | "dual_write" | "cutover";
}

export async function resolveShard(
  env: Env,
  domain: "social" | "guild",
  key: string,
): Promise<ShardResolution> {
  const bucket = shardFor(key, domain === "social" ? 16 : 32);
  const row = await env.IDENTITY_DB.prepare(
    `SELECT generation,binding_name,read_binding_name,state
       FROM shard_map WHERE domain=?1 AND bucket=?2 AND state IN ('active','dual_write','cutover')
       ORDER BY generation DESC LIMIT 1`,
  )
    .bind(domain, bucket)
    .first<{
      generation: number;
      binding_name: string;
      read_binding_name: string | null;
      state: "active" | "dual_write" | "cutover";
    }>();
  if (!row) throw new Error(`No shard mapping for ${domain}:${bucket}`);
  return {
    domain,
    bucket,
    generation: row.generation,
    primaryBinding: row.binding_name,
    dualReadBinding: row.read_binding_name,
    state: row.state,
  };
}

export function databaseBinding(env: Env, binding: string): D1Database {
  const value = (env as unknown as Record<string, unknown>)[binding];
  if (!value || typeof value !== "object")
    throw new Error(`D1 binding ${binding} is unavailable`);
  return value as D1Database;
}

export async function shardDatabases(
  env: Env,
  domain: "social" | "guild",
  key: string,
): Promise<{
  resolution: ShardResolution;
  primary: D1Database;
  dualRead: D1Database | null;
}> {
  const resolution = await resolveShard(env, domain, key);
  return {
    resolution,
    primary: databaseBinding(env, resolution.primaryBinding),
    dualRead: resolution.dualReadBinding
      ? databaseBinding(env, resolution.dualReadBinding)
      : null,
  };
}

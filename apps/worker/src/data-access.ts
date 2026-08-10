import type { Env } from "./env";
import { shardDatabases, type ShardResolution } from "./shard-router";

export interface RoutedDatabase {
  db: D1Database;
  dualRead: D1Database | null;
  resolution: ShardResolution;
}

export class ShardCutoverError extends Error {
  constructor(readonly resolution: ShardResolution) {
    super(
      `Shard ${resolution.domain}:${resolution.bucket} is in cutover; retry the write`,
    );
    this.name = "ShardCutoverError";
  }
}

export async function socialDatabase(
  env: Env,
  userId: string,
): Promise<RoutedDatabase> {
  const routed = await shardDatabases(env, "social", userId);
  return {
    db: routeDatabase(routed.primary, routed.dualRead, routed.resolution),
    dualRead: routed.dualRead,
    resolution: routed.resolution,
  };
}

export async function guildDatabase(
  env: Env,
  guildId: string,
): Promise<RoutedDatabase> {
  const routed = await shardDatabases(env, "guild", guildId);
  return {
    db: routeDatabase(routed.primary, routed.dualRead, routed.resolution),
    dualRead: routed.dualRead,
    resolution: routed.resolution,
  };
}

function routeDatabase(
  primary: D1Database,
  secondary: D1Database | null,
  resolution: ShardResolution,
): D1Database {
  if (!secondary) return primary;
  type StatementPair = {
    primary: D1PreparedStatement;
    secondary: D1PreparedStatement;
  };
  const pairs = new WeakMap<object, StatementPair>();
  const prepare = (query: string): D1PreparedStatement => {
    let pair: StatementPair = {
      primary: primary.prepare(query),
      secondary: secondary.prepare(query),
    };
    const wrapper = {
      bind(...values: unknown[]) {
        pair = {
          primary: pair.primary.bind(...values),
          secondary: pair.secondary.bind(...values),
        };
        pairs.set(wrapper, pair);
        return wrapper;
      },
      async first<T = Record<string, unknown>>(
        column?: string,
      ): Promise<T | null> {
        const result = column
          ? await pair.primary.first<T>(column)
          : await pair.primary.first<T>();
        if (result !== null) return result;
        return column
          ? pair.secondary.first<T>(column)
          : pair.secondary.first<T>();
      },
      async all<T = Record<string, unknown>>(): Promise<D1Result<T>> {
        const result = await pair.primary.all<T>();
        return result.results.length > 0 ? result : pair.secondary.all<T>();
      },
      async raw<T = unknown[]>(options?: { columnNames?: boolean }) {
        const result = options?.columnNames
          ? await pair.primary.raw<T>({ columnNames: true })
          : await pair.primary.raw<T>();
        if (result.length > 0) return result;
        return options?.columnNames
          ? pair.secondary.raw<T>({ columnNames: true })
          : pair.secondary.raw<T>();
      },
      async run<T = Record<string, unknown>>(): Promise<D1Result<T>> {
        if (resolution.state === "cutover")
          throw new ShardCutoverError(resolution);
        const result = await pair.primary.run<T>();
        if (resolution.state === "dual_write") await pair.secondary.run<T>();
        return result;
      },
    };
    pairs.set(wrapper, pair);
    return wrapper as unknown as D1PreparedStatement;
  };
  return {
    prepare,
    async batch<T = unknown>(statements: D1PreparedStatement[]) {
      if (resolution.state === "cutover")
        throw new ShardCutoverError(resolution);
      const statementPairs = statements.map((statement) => {
        const pair = pairs.get(statement as object);
        if (!pair)
          throw new Error("A routed D1 batch received a foreign statement");
        return pair;
      });
      const result = await primary.batch<T>(
        statementPairs.map((pair) => pair.primary),
      );
      if (resolution.state === "dual_write")
        await secondary.batch<T>(statementPairs.map((pair) => pair.secondary));
      return result;
    },
    async exec(query: string) {
      if (resolution.state === "cutover")
        throw new ShardCutoverError(resolution);
      const result = await primary.exec(query);
      if (resolution.state === "dual_write") await secondary.exec(query);
      return result;
    },
    withSession(constraintOrBookmark) {
      return primary.withSession(constraintOrBookmark);
    },
    dump() {
      return primary.dump();
    },
  } as D1Database;
}

export type ResourceType = "guild_channel" | "conversation" | "dm_channel";

export async function registerResource(
  env: Env,
  resourceId: string,
  resourceType: ResourceType,
  ownerId: string,
  createdAt: string,
): Promise<void> {
  await env.IDENTITY_DB.prepare(
    `INSERT INTO resource_directory(resource_id,resource_type,owner_id,created_at)
     VALUES (?1,?2,?3,?4)
     ON CONFLICT(resource_id) DO UPDATE SET
       resource_type=excluded.resource_type, owner_id=excluded.owner_id`,
  )
    .bind(resourceId, resourceType, ownerId, createdAt)
    .run();
}

export async function locateResource(
  env: Env,
  resourceId: string,
): Promise<{ resourceType: ResourceType; ownerId: string } | null> {
  const row = await env.IDENTITY_DB.prepare(
    "SELECT resource_type,owner_id FROM resource_directory WHERE resource_id=?1",
  )
    .bind(resourceId)
    .first<{ resource_type: ResourceType; owner_id: string }>();
  return row
    ? { resourceType: row.resource_type, ownerId: row.owner_id }
    : null;
}

export async function channelDatabase(
  env: Env,
  channelId: string,
): Promise<
  | ({ kind: "guild"; ownerId: string } & RoutedDatabase)
  | ({ kind: "social"; ownerId: string } & RoutedDatabase)
  | null
> {
  const resource = await locateResource(env, channelId);
  if (!resource) return null;
  if (resource.resourceType === "guild_channel") {
    return {
      kind: "guild",
      ownerId: resource.ownerId,
      ...(await guildDatabase(env, resource.ownerId)),
    };
  }
  return {
    kind: "social",
    ownerId: resource.ownerId,
    ...(await socialDatabase(env, resource.ownerId)),
  };
}

export async function firstWithDualRead<T>(
  routed: RoutedDatabase,
  query: (db: D1Database) => D1PreparedStatement,
): Promise<T | null> {
  const primary = await query(routed.db).first<T>();
  if (primary || !routed.dualRead) return primary;
  return query(routed.dualRead).first<T>();
}

export function shardFor(key: string, shardCount: number): number {
  if (!Number.isInteger(shardCount) || shardCount < 1)
    throw new RangeError("invalid shard count");
  let hash = 0xcbf29ce484222325n;
  for (const byte of new TextEncoder().encode(key)) {
    hash ^= BigInt(byte);
    hash = BigInt.asUintN(64, hash * 0x100000001b3n);
  }
  return Number(hash % BigInt(shardCount));
}

export function shardBinding(prefix: string, shard: number): string {
  return `${prefix}_${shard.toString().padStart(2, "0")}`;
}

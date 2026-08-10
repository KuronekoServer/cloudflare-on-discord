export const DISCORD_EPOCH = 1_420_070_400_000n;

export function composeSnowflake(
  timestampMs: number,
  workerId: number,
  sequence: number,
): string {
  if (!Number.isInteger(workerId) || workerId < 0 || workerId > 1023) {
    throw new RangeError("workerId must be an integer between 0 and 1023");
  }
  if (!Number.isInteger(sequence) || sequence < 0 || sequence > 4095) {
    throw new RangeError("sequence must be an integer between 0 and 4095");
  }
  const timestamp = BigInt(timestampMs) - DISCORD_EPOCH;
  if (timestamp < 0n || timestamp >= 1n << 42n)
    throw new RangeError("timestamp is out of range");
  return (
    (timestamp << 22n) |
    (BigInt(workerId) << 12n) |
    BigInt(sequence)
  ).toString();
}

export function snowflakeTimestamp(id: string): number {
  return Number((BigInt(id) >> 22n) + DISCORD_EPOCH);
}

export function snowflakeShardFor(key: string, count = 1024): number {
  let hash = 2166136261;
  for (let index = 0; index < key.length; index += 1) {
    hash ^= key.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0) % count;
}

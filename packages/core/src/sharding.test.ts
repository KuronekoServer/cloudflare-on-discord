import { describe, expect, it } from "vitest";
import { shardBinding, shardFor } from "./sharding";

describe("fixed pool sharding", () => {
  it("routes deterministically within the configured pool", () => {
    expect(shardFor("123456789012345678", 32)).toBe(
      shardFor("123456789012345678", 32),
    );
    expect(shardFor("123456789012345678", 32)).toBeLessThan(32);
  });

  it("formats bindings with stable two-digit buckets", () => {
    expect(shardBinding("SOCIAL_DB", 3)).toBe("SOCIAL_DB_03");
    expect(shardBinding("GUILD_DB", 31)).toBe("GUILD_DB_31");
  });
});

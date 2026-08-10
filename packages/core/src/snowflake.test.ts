import { describe, expect, it } from "vitest";
import { composeSnowflake, snowflakeTimestamp } from "./snowflake";

describe("snowflakes", () => {
  it("round trips the timestamp", () => {
    const timestamp = Date.UTC(2026, 7, 10, 0, 0, 0);
    const id = composeSnowflake(timestamp, 12, 3);
    expect(id).toMatch(/^\d{17,20}$/);
    expect(snowflakeTimestamp(id)).toBe(timestamp);
  });
});

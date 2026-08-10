import { describe, expect, it } from "vitest";
import type { Env } from "./env";
import { getOptionalSecret, getSecret } from "./secrets";

describe("Secrets Store resolution", () => {
  it("requires the Secrets Store binding in production", async () => {
    const env = {
      ENVIRONMENT: "prod",
      JWT_SIGNING_KEY: "legacy-production-secret",
    } as unknown as Env;
    await expect(getSecret(env, "JWT_SIGNING_KEY")).rejects.toThrow(
      "Secrets Store binding",
    );
  });

  it("reads an async Secrets Store binding without exposing its value", async () => {
    const env = {
      ENVIRONMENT: "prod",
      JWT_SIGNING_KEY_SECRET: { get: async () => "stored-value" },
    } as unknown as Env;
    await expect(getSecret(env, "JWT_SIGNING_KEY")).resolves.toBe(
      "stored-value",
    );
  });

  it("keeps optional production integrations disabled when unbound", async () => {
    const env = { ENVIRONMENT: "prod" } as unknown as Env;
    await expect(
      getOptionalSecret(env, "REALTIME_API_TOKEN"),
    ).resolves.toBeUndefined();
  });
});

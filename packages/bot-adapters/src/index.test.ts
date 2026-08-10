import { describe, expect, it } from "vitest";
import {
  cloudCordBotEndpoints,
  discordJsAdapter,
  normalizeOrigin,
} from "./index";

describe("bot adapters", () => {
  it("builds fixed Discord v10 endpoints", () => {
    expect(cloudCordBotEndpoints("https://chat.example.test/")).toEqual({
      origin: "https://chat.example.test",
      api: "https://chat.example.test/api/v10",
      gatewayDiscovery: "https://chat.example.test/api/v10/gateway/bot",
      compatibility: "https://chat.example.test/api/v10/compatibility",
    });
    expect(discordJsAdapter("http://127.0.0.1:8787")).toEqual({
      rest: { api: "http://127.0.0.1:8787/api/v10" },
    });
  });

  it("rejects insecure remote and credentialed origins", () => {
    expect(() => normalizeOrigin("http://chat.example.test")).toThrow();
    expect(() => normalizeOrigin("https://user:secret@example.test")).toThrow();
  });
});

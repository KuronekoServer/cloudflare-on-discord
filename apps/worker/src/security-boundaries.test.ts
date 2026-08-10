import { describe, expect, it } from "vitest";
import { asyncApi, openApi } from "./spec";
import { mimeMatches, validInstanceSetting } from "./validation";

describe("security boundaries", () => {
  it("accepts known magic bytes and rejects active-content declarations", () => {
    expect(
      mimeMatches(
        "image/png",
        new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
      ),
    ).toBe(true);
    expect(mimeMatches("image/png", new TextEncoder().encode("<script>"))).toBe(
      false,
    );
    expect(mimeMatches("text/html", new TextEncoder().encode("<p>x</p>"))).toBe(
      false,
    );
  });

  it("bounds every mutable instance setting", () => {
    expect(validInstanceSetting("registration.enabled", "false")).toBe(true);
    expect(validInstanceSetting("registration.enabled", "yes")).toBe(false);
    expect(validInstanceSetting("upload.file.bytes", "52428800")).toBe(true);
    expect(validInstanceSetting("upload.file.bytes", "999999999999")).toBe(
      false,
    );
    expect(validInstanceSetting("voice.warning_gb_per_hour", "0.15")).toBe(
      true,
    );
    expect(validInstanceSetting("export.retention_days", "91")).toBe(false);
  });

  it("publishes the first-party HTTP and realtime contracts", () => {
    const http = openApi("https://chat.example.test");
    const realtime = asyncApi("https://chat.example.test");
    expect(http.paths).toHaveProperty("/auth/desktop/token");
    expect(http.paths).toHaveProperty("/channels/{channelId}/threads");
    expect(http.paths).toHaveProperty("/oauth2/authorize");
    expect(realtime.channels).toHaveProperty("voiceControl");
    expect(JSON.stringify({ http, realtime }).toLowerCase()).not.toContain(
      "recording",
    );
  });
});

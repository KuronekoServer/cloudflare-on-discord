export const SUPPORTED_BOT_LIBRARIES = Object.freeze({
  discordJs: "14.27.0",
  discordPy: "2.7.1",
  jda: "6.4.2",
});

export interface CloudCordBotEndpoints {
  origin: string;
  api: string;
  gatewayDiscovery: string;
  compatibility: string;
}

export function cloudCordBotEndpoints(origin: string): CloudCordBotEndpoints {
  const normalized = normalizeOrigin(origin);
  return {
    origin: normalized,
    api: `${normalized}/api/v10`,
    gatewayDiscovery: `${normalized}/api/v10/gateway/bot`,
    compatibility: `${normalized}/api/v10/compatibility`,
  };
}

/**
 * Spread this into discord.js ClientOptions. discord.js passes `rest` to
 * @discordjs/rest, which discovers the Gateway from this same API origin.
 */
export function discordJsAdapter(origin: string) {
  return {
    rest: { api: cloudCordBotEndpoints(origin).api },
  } as const;
}

export function normalizeOrigin(origin: string): string {
  const url = new URL(origin);
  if (url.protocol !== "https:" && !isLocalhost(url))
    throw new TypeError("CloudCord Bot API origin must use HTTPS");
  if (url.username || url.password || url.search || url.hash)
    throw new TypeError(
      "CloudCord Bot API origin must not contain credentials or a query",
    );
  url.pathname = url.pathname.replace(/\/+$/, "");
  return url.toString().replace(/\/$/, "");
}

function isLocalhost(url: URL): boolean {
  return (
    url.protocol === "http:" &&
    ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)
  );
}

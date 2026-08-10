export function upgradeWebSocket(
  state: DurableObjectState,
  request: Request,
  tags: string[] = [],
): Response {
  if (request.headers.get("upgrade")?.toLowerCase() !== "websocket") {
    return new Response("WebSocket upgrade required", { status: 426 });
  }
  const pair = new WebSocketPair();
  const client = pair[0];
  const server = pair[1];
  state.acceptWebSocket(server, tags);
  return new Response(null, { status: 101, webSocket: client });
}

export function broadcast(
  state: DurableObjectState,
  payload: unknown,
  except?: WebSocket,
): void {
  const encoded = JSON.stringify(payload);
  for (const socket of state.getWebSockets()) {
    if (socket === except) continue;
    try {
      socket.send(encoded);
    } catch {
      socket.close(1011, "Delivery failed");
    }
  }
}

export async function readJson<T>(request: Request): Promise<T> {
  if (!request.headers.get("content-type")?.includes("application/json"))
    throw new Error("Expected JSON");
  return request.json<T>();
}

export function json(value: unknown, init: ResponseInit = {}): Response {
  const headers = new Headers(init.headers);
  headers.set("content-type", "application/json; charset=utf-8");
  return new Response(JSON.stringify(value), { ...init, headers });
}

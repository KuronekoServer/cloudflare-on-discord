const endpoint = process.env.CLOUDCORD_WS_URL;
const apiBase = process.env.CLOUDCORD_API_BASE;
const accessToken = process.env.CLOUDCORD_ACCESS_TOKEN;
const count = Number(process.env.CLOUDCORD_CONNECTIONS ?? 100);
if (!endpoint || !apiBase || !accessToken)
  throw new Error(
    "CLOUDCORD_WS_URL, CLOUDCORD_API_BASE, and CLOUDCORD_ACCESS_TOKEN are required",
  );

const sockets = [];
let opened = 0;
let failed = 0;
for (let index = 0; index < count; index += 1) {
  const ticketResponse = await fetch(`${apiBase}/ws-ticket`, {
    method: "POST",
    headers: { authorization: `Bearer ${accessToken}` },
  });
  if (!ticketResponse.ok)
    throw new Error(`Ticket request failed: ${ticketResponse.status}`);
  const { ticket } = await ticketResponse.json();
  const url = new URL(endpoint);
  url.searchParams.set("ticket", ticket);
  const socket = new WebSocket(url);
  socket.addEventListener("open", () => {
    opened += 1;
    socket.send(JSON.stringify({ op: 1, data: { index } }));
  });
  socket.addEventListener("error", () => {
    failed += 1;
  });
  sockets.push(socket);
}

const report = setInterval(
  () =>
    console.log(
      JSON.stringify({
        requested: count,
        opened,
        failed,
        at: new Date().toISOString(),
      }),
    ),
  5_000,
);
process.on("SIGINT", () => {
  clearInterval(report);
  for (const socket of sockets) socket.close(1000, "Harness stopped");
  process.exit(0);
});

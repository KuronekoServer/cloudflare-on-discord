import { readFile } from "node:fs/promises";
import { chromium } from "playwright";

const apiBase = process.env.CLOUDCORD_API_BASE;
const channelId = process.env.CLOUDCORD_VOICE_CHANNEL_ID;
const tokenFile = process.env.CLOUDCORD_ACCESS_TOKENS_FILE;
const peerLimit = Number(process.env.CLOUDCORD_WEBRTC_PEERS ?? 20);
const soakSeconds = Number(process.env.CLOUDCORD_SOAK_SECONDS ?? 300);
const concurrency = Number(process.env.CLOUDCORD_CONNECT_CONCURRENCY ?? 10);

if (!apiBase || !channelId || !tokenFile)
  throw new Error(
    "CLOUDCORD_API_BASE, CLOUDCORD_VOICE_CHANNEL_ID, and CLOUDCORD_ACCESS_TOKENS_FILE are required",
  );
if (!Number.isInteger(peerLimit) || peerLimit < 1 || peerLimit > 500)
  throw new Error("CLOUDCORD_WEBRTC_PEERS must be between 1 and 500");
if (!Number.isFinite(soakSeconds) || soakSeconds < 1)
  throw new Error("CLOUDCORD_SOAK_SECONDS must be positive");

const parsed = JSON.parse(await readFile(tokenFile, "utf8"));
if (!Array.isArray(parsed) || parsed.some((token) => typeof token !== "string"))
  throw new Error("The token file must contain a JSON array of access tokens");
const tokens = parsed.slice(0, peerLimit);
if (tokens.length < peerLimit)
  throw new Error(
    `Token file contains ${tokens.length}; ${peerLimit} are required`,
  );

const browser = await chromium.launch({
  headless: true,
  args: [
    "--use-fake-device-for-media-stream",
    "--use-fake-ui-for-media-stream",
    "--autoplay-policy=no-user-gesture-required",
  ],
});
const context = await browser.newContext({ permissions: ["microphone"] });
const page = await context.newPage();
await page.goto(new URL("/health", apiBase).toString());

const startedAt = Date.now();
const connections = await page.evaluate(
  async ({ apiBase, channelId, tokens, concurrency }) => {
    const peers = [];
    globalThis.__cloudcordLoadPeers = peers;
    const request = async (token, path, init = {}) => {
      const response = await fetch(`${apiBase}${path}`, {
        ...init,
        headers: {
          authorization: `Bearer ${token}`,
          "content-type": "application/json",
          "idempotency-key": crypto.randomUUID(),
          ...init.headers,
        },
      });
      if (!response.ok)
        throw new Error(`${path}: ${response.status} ${await response.text()}`);
      return response.status === 204 ? null : response.json();
    };
    const connect = async (token, index) => {
      const began = performance.now();
      let stream;
      let pc;
      try {
        await request(token, `/voice/${channelId}/join`, {
          method: "POST",
          body: JSON.stringify({
            muted: false,
            deafened: false,
            camera: false,
          }),
        });
        const session = await request(token, "/realtime/sessions", {
          method: "POST",
          body: JSON.stringify({ channelId }),
        });
        stream = await navigator.mediaDevices.getUserMedia({
          audio: { channelCount: 1 },
          video: false,
        });
        pc = new RTCPeerConnection({ bundlePolicy: "max-bundle" });
        const transceiver = pc.addTransceiver(stream.getAudioTracks()[0], {
          direction: "sendrecv",
          streams: [stream],
          sendEncodings: [{ maxBitrate: 32_000 }],
        });
        const opus = RTCRtpSender.getCapabilities("audio")?.codecs.filter(
          (codec) => codec.mimeType.toLowerCase() === "audio/opus",
        );
        if (opus?.length) transceiver.setCodecPreferences(opus);
        const offer = await pc.createOffer();
        const sdp = offer.sdp?.replace(
          /^(a=fmtp:\d+ .*)$/imu,
          (line) => `${line};usedtx=1;stereo=0`,
        );
        await pc.setLocalDescription({ type: offer.type, sdp });
        const trackName = `load-audio-${crypto.randomUUID()}`;
        const negotiated = await request(
          token,
          `/realtime/sessions/${session.sessionId}/tracks`,
          {
            method: "POST",
            body: JSON.stringify({
              channelId,
              sessionDescription: pc.localDescription,
              tracks: [
                {
                  location: "local",
                  mid: transceiver.mid,
                  trackName,
                  kind: "audio",
                  label: "microphone",
                },
              ],
            }),
          },
        );
        if (negotiated.sessionDescription)
          await pc.setRemoteDescription(negotiated.sessionDescription);
        peers.push({
          token,
          pc,
          stream,
          sessionId: session.sessionId,
          trackName,
        });
        return {
          index,
          ok: true,
          sessionId: session.sessionId,
          connectMs: Math.round(performance.now() - began),
        };
      } catch (error) {
        stream?.getTracks().forEach((track) => track.stop());
        pc?.close();
        return { index, ok: false, error: String(error) };
      }
    };
    const results = [];
    for (let offset = 0; offset < tokens.length; offset += concurrency) {
      results.push(
        ...(await Promise.all(
          tokens
            .slice(offset, offset + concurrency)
            .map((token, index) => connect(token, offset + index)),
        )),
      );
    }
    return results;
  },
  { apiBase, channelId, tokens, concurrency },
);

const successful = connections.filter((entry) => entry.ok);
console.log(
  JSON.stringify({
    phase: "connected",
    requested: peerLimit,
    connected: successful.length,
    failed: connections.length - successful.length,
    p95ConnectMs: percentile(
      successful.map((entry) => entry.connectMs),
      0.95,
    ),
    elapsedMs: Date.now() - startedAt,
    failures: connections.filter((entry) => !entry.ok).slice(0, 10),
  }),
);

await new Promise((resolve) => setTimeout(resolve, soakSeconds * 1000));
const stats = await page.evaluate(
  async ({ apiBase, channelId }) => {
    const peers = globalThis.__cloudcordLoadPeers ?? [];
    let bytesSent = 0;
    let bytesReceived = 0;
    for (const peer of peers) {
      const reports = await peer.pc.getStats();
      for (const report of reports.values()) {
        if (report.type === "outbound-rtp" && report.kind === "audio")
          bytesSent += report.bytesSent ?? 0;
        if (report.type === "inbound-rtp" && report.kind === "audio")
          bytesReceived += report.bytesReceived ?? 0;
      }
      peer.stream.getTracks().forEach((track) => track.stop());
      peer.pc.close();
      await fetch(`${apiBase}/voice/${channelId}`, {
        method: "DELETE",
        headers: {
          authorization: `Bearer ${peer.token}`,
          "idempotency-key": crypto.randomUUID(),
        },
      }).catch(() => undefined);
    }
    return { peers: peers.length, bytesSent, bytesReceived };
  },
  { apiBase, channelId },
);
await browser.close();

console.log(
  JSON.stringify({
    phase: "complete",
    soakSeconds,
    ...stats,
    participantHours: (stats.peers * soakSeconds) / 3600,
    downstreamGbPerParticipantHour:
      stats.peers === 0
        ? 0
        : stats.bytesReceived /
          1_000_000_000 /
          ((stats.peers * soakSeconds) / 3600),
  }),
);

function percentile(values, quantile) {
  if (values.length === 0) return null;
  const sorted = [...values].sort((left, right) => left - right);
  return sorted[
    Math.min(Math.ceil(sorted.length * quantile) - 1, sorted.length - 1)
  ];
}

import { normalizeOrigin } from "@cloudcord/bot-adapters";

export interface AudioTrackLike {
  id: string;
  stop(): void;
}

export interface AudioSourceLike {
  createTrack(): AudioTrackLike;
  onData(data: {
    samples: Int16Array;
    sampleRate: 48_000;
    bitsPerSample: 16;
    channelCount: 1;
    numberOfFrames: 480;
  }): void;
}

export interface PeerConnectionLike {
  addTransceiver(
    track: AudioTrackLike,
    init: { direction: "sendonly" },
  ): { mid: string | null };
  createOffer(): Promise<{ type: string; sdp?: string }>;
  createAnswer(): Promise<{ type: string; sdp?: string }>;
  setLocalDescription(description: {
    type: string;
    sdp?: string;
  }): Promise<void>;
  setRemoteDescription(description: {
    type: string;
    sdp?: string;
  }): Promise<void>;
  close(): void;
}

export interface NodeWebRtcRuntime {
  createAudioSource(): AudioSourceLike;
  createPeerConnection(configuration: {
    bundlePolicy: "max-bundle";
  }): PeerConnectionLike;
}

export interface OpusDecoder {
  /** Decode one Opus packet to signed 48 kHz mono PCM. */
  decode(packet: Uint8Array): Int16Array;
}

export interface VoiceAdapterOptions {
  origin: string;
  token: string;
  channelId: string;
  webRtc: NodeWebRtcRuntime;
  opusDecoder?: OpusDecoder;
  fetch?: typeof globalThis.fetch;
}

/**
 * Live-only PCM/Opus bridge for Cloudflare Realtime.
 *
 * It intentionally has no file, replay buffer, persistence, or capture-history
 * API. PCM frames are handed directly to the WebRTC audio source.
 */
export class CloudCordVoiceAdapter {
  private readonly api: string;
  private readonly request: typeof globalThis.fetch;
  private readonly source: AudioSourceLike;
  private readonly track: AudioTrackLike;
  private readonly peer: PeerConnectionLike;
  private sessionId: string | null = null;
  private trackName: string | null = null;
  private closed = false;

  constructor(private readonly options: VoiceAdapterOptions) {
    this.api = `${normalizeOrigin(options.origin)}/api/v10`;
    this.request = options.fetch ?? globalThis.fetch;
    this.source = options.webRtc.createAudioSource();
    this.track = this.source.createTrack();
    this.peer = options.webRtc.createPeerConnection({
      bundlePolicy: "max-bundle",
    });
  }

  async connect(): Promise<void> {
    this.assertOpen();
    await this.json(`/voice/${this.options.channelId}/join`, {
      method: "POST",
      body: "{}",
    });
    const session = await this.json<{ sessionId: string }>(
      `/voice/${this.options.channelId}/sessions`,
      { method: "POST", body: "{}" },
    );
    this.sessionId = session.sessionId;
    this.trackName = `bot-microphone-${crypto.randomUUID()}`;
    this.peer.addTransceiver(this.track, { direction: "sendonly" });
    const offer = await this.peer.createOffer();
    const local = { type: offer.type, sdp: enableOpusDtx(offer.sdp ?? "") };
    await this.peer.setLocalDescription(local);
    const result = await this.json<{
      sessionDescription?: { type: string; sdp?: string };
    }>(
      `/voice/${this.options.channelId}/sessions/${session.sessionId}/tracks`,
      {
        method: "POST",
        body: JSON.stringify({
          sessionDescription: local,
          tracks: [
            {
              location: "local",
              trackName: this.trackName,
              kind: "audio",
              label: "microphone",
            },
          ],
        }),
      },
    );
    if (result.sessionDescription?.type === "answer") {
      await this.peer.setRemoteDescription(result.sessionDescription);
    } else if (result.sessionDescription?.type === "offer") {
      await this.peer.setRemoteDescription(result.sessionDescription);
      const answer = await this.peer.createAnswer();
      await this.peer.setLocalDescription(answer);
      await this.json(
        `/voice/${this.options.channelId}/sessions/${session.sessionId}/renegotiate`,
        { method: "PUT", body: JSON.stringify({ sessionDescription: answer }) },
      );
    }
  }

  writePcm(samples: Int16Array): void {
    this.assertOpen();
    if (samples.length === 0 || samples.length % 480 !== 0)
      throw new RangeError(
        "PCM must contain whole 10 ms frames at 48 kHz mono",
      );
    for (let offset = 0; offset < samples.length; offset += 480)
      this.source.onData({
        samples: samples.slice(offset, offset + 480),
        sampleRate: 48_000,
        bitsPerSample: 16,
        channelCount: 1,
        numberOfFrames: 480,
      });
  }

  writeOpus(packet: Uint8Array): void {
    if (!this.options.opusDecoder)
      throw new Error("An Opus decoder must be supplied for Opus input");
    this.writePcm(this.options.opusDecoder.decode(packet));
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    try {
      if (this.sessionId && this.trackName)
        await this.json(
          `/voice/${this.options.channelId}/sessions/${this.sessionId}/tracks`,
          {
            method: "DELETE",
            body: JSON.stringify({ trackNames: [this.trackName] }),
          },
        );
      await this.json(`/voice/${this.options.channelId}`, { method: "DELETE" });
    } finally {
      this.track.stop();
      this.peer.close();
      this.sessionId = null;
      this.trackName = null;
    }
  }

  private async json<T = unknown>(path: string, init: RequestInit): Promise<T> {
    const response = await this.request(`${this.api}${path}`, {
      ...init,
      headers: {
        authorization: `Bot ${this.options.token}`,
        "content-type": "application/json",
      },
    });
    if (!response.ok) {
      const detail = (await response.text()).slice(0, 1000);
      throw new Error(
        `CloudCord voice request failed (${response.status}): ${detail}`,
      );
    }
    return response.status === 204 ? (undefined as T) : response.json<T>();
  }

  private assertOpen(): void {
    if (this.closed) throw new Error("Voice adapter is closed");
  }
}

export function enableOpusDtx(sdp: string): string {
  return sdp.replace(
    /a=fmtp:(\d+) ([^\r\n]*useinbandfec=1[^\r\n]*)/g,
    (_line, payload: string, parameters: string) => {
      const filtered = parameters
        .split(";")
        .filter((value: string) => !/^\s*(usedtx|stereo)=/.test(value));
      return `a=fmtp:${payload} ${filtered.join(";")};usedtx=1;stereo=0`;
    },
  );
}

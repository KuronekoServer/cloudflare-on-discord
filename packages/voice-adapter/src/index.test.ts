import { describe, expect, it, vi } from "vitest";
import { CloudCordVoiceAdapter, enableOpusDtx } from "./index";

describe("voice adapter", () => {
  it("enables mono Opus DTX", () => {
    expect(
      enableOpusDtx("a=fmtp:111 minptime=10;useinbandfec=1\r\n"),
    ).toContain("useinbandfec=1;usedtx=1;stereo=0");
  });

  it("passes PCM directly in 10 ms frames", () => {
    const onData = vi.fn();
    const adapter = new CloudCordVoiceAdapter({
      origin: "http://127.0.0.1:8787",
      token: "test",
      channelId: "1",
      fetch: vi.fn() as unknown as typeof fetch,
      webRtc: {
        createAudioSource: () => ({
          createTrack: () => ({ id: "track", stop: vi.fn() }),
          onData,
        }),
        createPeerConnection: () => ({
          addTransceiver: () => ({ mid: null }),
          createOffer: vi.fn(),
          createAnswer: vi.fn(),
          setLocalDescription: vi.fn(),
          setRemoteDescription: vi.fn(),
          close: vi.fn(),
        }),
      },
    });
    adapter.writePcm(new Int16Array(960));
    expect(onData).toHaveBeenCalledTimes(2);
    expect(() => adapter.writePcm(new Int16Array(481))).toThrow(RangeError);
  });
});

import { describe, expect, it } from "vitest";
import { selectVoiceSubscriptions, type VoiceCandidate } from "./voice";

const candidate = (
  index: number,
  values: Partial<VoiceCandidate> = {},
): VoiceCandidate => ({
  userId: String(index),
  level: index / 20,
  speaking: false,
  lastSpokeAt: 0,
  priority: false,
  pinned: false,
  ...values,
});

describe("selectVoiceSubscriptions", () => {
  it("subscribes to everyone in a room of ten or fewer", () => {
    const members = Array.from({ length: 10 }, (_, index) => candidate(index));
    expect(selectVoiceSubscriptions(members, "0")).toHaveLength(9);
  });

  it("caps large rooms at eight while preserving pinned speakers", () => {
    const members = Array.from({ length: 20 }, (_, index) => candidate(index));
    members[1] = candidate(1, { pinned: true, level: 0 });
    const selected = selectVoiceSubscriptions(members, "0", 1_000);
    expect(selected).toHaveLength(8);
    expect(selected).toContain("1");
  });
});

export interface VoiceCandidate {
  userId: string;
  level: number;
  speaking: boolean;
  lastSpokeAt: number;
  priority: boolean;
  pinned: boolean;
}

export function selectVoiceSubscriptions(
  candidates: readonly VoiceCandidate[],
  receiverId: string,
  now = Date.now(),
  maximum = 8,
): string[] {
  const others = candidates.filter(
    (candidate) => candidate.userId !== receiverId,
  );
  if (candidates.length <= 10)
    return others.map((candidate) => candidate.userId);
  return [...others]
    .sort((left, right) => {
      const leftPinned = Number(left.pinned || left.priority);
      const rightPinned = Number(right.pinned || right.priority);
      if (leftPinned !== rightPinned) return rightPinned - leftPinned;
      const leftHeld = Number(left.speaking || now - left.lastSpokeAt <= 750);
      const rightHeld = Number(
        right.speaking || now - right.lastSpokeAt <= 750,
      );
      if (leftHeld !== rightHeld) return rightHeld - leftHeld;
      if (left.level !== right.level) return right.level - left.level;
      return left.userId.localeCompare(right.userId);
    })
    .slice(0, maximum)
    .map((candidate) => candidate.userId);
}

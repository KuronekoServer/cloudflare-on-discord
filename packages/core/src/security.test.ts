import { describe, expect, it } from "vitest";
import { hashPassword, verifyPassword } from "./security";

describe("password hashing", () => {
  it("uses Argon2id and rejects the wrong password", async () => {
    const encoded = await hashPassword("correct horse battery staple");
    expect(encoded).toMatch(/^\$argon2id\$v=19\$/);
    await expect(
      verifyPassword(encoded, "correct horse battery staple"),
    ).resolves.toBe(true);
    await expect(verifyPassword(encoded, "wrong password")).resolves.toBe(
      false,
    );
  });
});

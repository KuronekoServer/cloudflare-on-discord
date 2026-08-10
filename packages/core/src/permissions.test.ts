import { describe, expect, it } from "vitest";
import { PermissionFlags } from "@cloudcord/contracts";
import { calculatePermissions, hasPermission } from "./permissions";

describe("calculatePermissions", () => {
  it("applies role and member overwrites in Discord order", () => {
    const result = calculatePermissions({
      guildOwnerId: "1",
      memberId: "2",
      everyoneRoleId: "10",
      memberRoleIds: ["11"],
      roles: [
        {
          id: "10",
          position: 0,
          permissions: PermissionFlags.VIEW_CHANNEL.toString(),
        },
        {
          id: "11",
          position: 1,
          permissions: PermissionFlags.SEND_MESSAGES.toString(),
        },
      ],
      overwrites: [
        {
          id: "10",
          type: "role",
          allow: "0",
          deny: PermissionFlags.SEND_MESSAGES.toString(),
        },
        {
          id: "11",
          type: "role",
          allow: PermissionFlags.SEND_MESSAGES.toString(),
          deny: "0",
        },
        {
          id: "2",
          type: "member",
          allow: "0",
          deny: PermissionFlags.VIEW_CHANNEL.toString(),
        },
      ],
    });
    expect(hasPermission(result, PermissionFlags.SEND_MESSAGES)).toBe(true);
    expect(hasPermission(result, PermissionFlags.VIEW_CHANNEL)).toBe(false);
  });

  it("grants all permissions to the guild owner", () => {
    const result = calculatePermissions({
      guildOwnerId: "1",
      memberId: "1",
      everyoneRoleId: "10",
      memberRoleIds: [],
      roles: [],
    });
    expect(hasPermission(result, PermissionFlags.BAN_MEMBERS)).toBe(true);
  });
});

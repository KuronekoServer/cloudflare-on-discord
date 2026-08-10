import { ALL_PERMISSIONS, PermissionFlags } from "@cloudcord/contracts";
import fc from "fast-check";
import { describe, it } from "vitest";
import { calculatePermissions } from "./permissions";

describe("permission evaluator properties", () => {
  it("always grants the complete bitset to an owner", () => {
    fc.assert(
      fc.property(
        fc.array(fc.bigInt({ min: 0n, max: ALL_PERMISSIONS })),
        (permissions) => {
          const result = calculatePermissions({
            guildOwnerId: "owner",
            memberId: "owner",
            everyoneRoleId: "everyone",
            memberRoleIds: [],
            roles: permissions.map((value, index) => ({
              id: String(index),
              position: index,
              permissions: value.toString(),
            })),
          });
          return result === ALL_PERMISSIONS;
        },
      ),
    );
  });

  it("administrator bypasses channel denies", () => {
    fc.assert(
      fc.property(fc.bigInt({ min: 0n, max: ALL_PERMISSIONS }), (deny) => {
        const result = calculatePermissions({
          guildOwnerId: "owner",
          memberId: "member",
          everyoneRoleId: "everyone",
          memberRoleIds: ["admin"],
          roles: [
            { id: "everyone", position: 0, permissions: "0" },
            {
              id: "admin",
              position: 1,
              permissions: PermissionFlags.ADMINISTRATOR.toString(),
            },
          ],
          overwrites: [
            { id: "member", type: "member", allow: "0", deny: deny.toString() },
          ],
        });
        return result === ALL_PERMISSIONS;
      }),
    );
  });
});

import {
  ALL_PERMISSIONS,
  PermissionFlags,
  type PermissionOverwrite,
  type RolePermissions,
} from "@cloudcord/contracts";

export interface PermissionContext {
  guildOwnerId: string;
  memberId: string;
  everyoneRoleId: string;
  roles: RolePermissions[];
  memberRoleIds: string[];
  overwrites?: PermissionOverwrite[];
}

function applyOverwrite(
  value: bigint,
  overwrite?: PermissionOverwrite,
): bigint {
  if (!overwrite) return value;
  return (value & ~BigInt(overwrite.deny)) | BigInt(overwrite.allow);
}

export function calculatePermissions(context: PermissionContext): bigint {
  if (context.memberId === context.guildOwnerId) return ALL_PERMISSIONS;

  const everyone = context.roles.find(
    (role) => role.id === context.everyoneRoleId,
  );
  let permissions = BigInt(everyone?.permissions ?? "0");
  for (const role of context.roles) {
    if (context.memberRoleIds.includes(role.id))
      permissions |= BigInt(role.permissions);
  }

  if ((permissions & PermissionFlags.ADMINISTRATOR) !== 0n)
    return ALL_PERMISSIONS;
  if (!context.overwrites) return permissions;

  permissions = applyOverwrite(
    permissions,
    context.overwrites.find(
      (overwrite) =>
        overwrite.type === "role" && overwrite.id === context.everyoneRoleId,
    ),
  );

  let roleAllow = 0n;
  let roleDeny = 0n;
  for (const overwrite of context.overwrites) {
    if (
      overwrite.type === "role" &&
      context.memberRoleIds.includes(overwrite.id)
    ) {
      roleAllow |= BigInt(overwrite.allow);
      roleDeny |= BigInt(overwrite.deny);
    }
  }
  permissions = (permissions & ~roleDeny) | roleAllow;

  return applyOverwrite(
    permissions,
    context.overwrites.find(
      (overwrite) =>
        overwrite.type === "member" && overwrite.id === context.memberId,
    ),
  );
}

export function hasPermission(value: bigint, permission: bigint): boolean {
  return (
    (value & PermissionFlags.ADMINISTRATOR) !== 0n ||
    (value & permission) === permission
  );
}

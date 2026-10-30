export type WorkspaceRole = "owner" | "admin" | "analyst" | "viewer";

export function canWriteAssets(role: string): role is Exclude<WorkspaceRole, "viewer"> {
  return role === "owner" || role === "admin" || role === "analyst";
}

export function canManageMemberRoles(role: string): role is "owner" {
  return role === "owner";
}

export function canManageIntegrations(role: string): boolean {
  return role === "owner" || role === "admin";
}

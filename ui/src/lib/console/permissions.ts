// Mirror of the API's wildcard rule (`services/admin_access.rs::matches`):
// a granted `ridm:users:*` covers `ridm:users:read`, `ridm:*` covers
// everything, and a required name is always concrete.

export function permissionMatches(granted: string, required: string): boolean {
  if (required.includes("*")) return false;
  if (granted === required) return true;
  if (!granted.endsWith(":*")) return false;
  const prefix = granted.slice(0, -2);
  if (!required.startsWith(prefix)) return false;
  const rest = required.slice(prefix.length);
  return rest.length > 1 && rest.startsWith(":") && !rest.includes("*");
}

export function hasPermission(granted: readonly string[], required: string | undefined): boolean {
  if (!required) return true;
  return granted.some((g) => permissionMatches(g, required));
}

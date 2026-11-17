/** I ruoli come li applica il server (ADR-0019, `ca_api.auth.authorize`): la UI li rispecchia solo
 * per mostrare o disattivare le azioni. Chi decide resta il server, che risponde 403. */
import type { Schemas } from "@/api/client";

type Role = Schemas["Role"];

export function canTriage(roles: readonly Role[]): boolean {
  return roles.includes("triage") || roles.includes("approvatore");
}

export function canApprove(roles: readonly Role[]): boolean {
  return roles.includes("approvatore");
}

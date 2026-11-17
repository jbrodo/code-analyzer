/** Risposte simulate dei test, ricavate dagli esempi dell'OpenAPI (W-02): nessun dato inventato. */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import type { Schemas } from "./client";

interface Document {
  components: { schemas: Record<string, { examples?: unknown[] }> };
}

const document = JSON.parse(
  // i test girano da `web/` (bun run --cwd web test)
  readFileSync(resolve(process.cwd(), "../schemas/openapi.json"), "utf8"),
) as Document;

/** Il primo esempio dichiarato per uno schema; fallisce se il contratto non ne ha. */
export function example<Name extends keyof Schemas>(name: Name): Schemas[Name] {
  const found = document.components.schemas[name]?.examples?.[0];
  if (found === undefined) throw new Error(`nessun esempio per ${name} in openapi.json`);
  return found as Schemas[Name];
}

export function jsonResponse(body: unknown, status = 200, type = "application/json"): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": type } });
}

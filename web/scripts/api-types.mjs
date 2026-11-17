// Genera src/api/schema.d.ts da schemas/openapi.json (W-02): i tipi dell'API non si scrivono a mano.
// `--check` non scrive: esce con 1 se il file versionato non coincide (fa parte di `bun run lint`).
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import openapiTS, { astToString } from "openapi-typescript";

const SOURCE = new URL("../../schemas/openapi.json", import.meta.url);
const TARGET = new URL("../src/api/schema.d.ts", import.meta.url);
const HEADER =
  "// GENERATO da schemas/openapi.json con `bun run types`: non modificare a mano.\n" +
  "// Il lint fallisce se non coincide con il contratto del server (ADR-0017).\n\n";

const ast = await openapiTS(SOURCE, { alphabetize: true, immutable: true });
const text = HEADER + astToString(ast);

if (process.argv.includes("--check")) {
  const current = existsSync(TARGET) ? readFileSync(TARGET, "utf8") : "";
  if (current !== text) {
    console.error("src/api/schema.d.ts non coincide con schemas/openapi.json: esegui `bun run types`");
    process.exit(1);
  }
} else {
  writeFileSync(TARGET, text);
}

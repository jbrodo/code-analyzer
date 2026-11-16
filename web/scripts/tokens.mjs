// Genera src/styles/tokens.css da doc/ux/tokens.json (U-02), senza trascrizione a mano.
// `--check` non scrive: esce con 1 se il file versionato non coincide (fa parte di `pnpm lint`).
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const SOURCE = new URL("../../doc/ux/tokens.json", import.meta.url);
const TARGET = new URL("../src/styles/tokens.css", import.meta.url);
const SAFE_VALUE = /^[#\w\s.,%()"-]+$/;

function cssValue(token) {
  const value = token.$value;
  if (token.$type === "fontFamily") {
    return value.map((name) => (/^[\w-]+$/.test(name) ? name : `"${name}"`)).join(", ");
  }
  if (token.$type === "cubicBezier") {
    return `cubic-bezier(${value.join(", ")})`;
  }
  return String(value);
}

function declarations(prefix, group) {
  return Object.entries(group).map(([name, token]) => {
    const value = cssValue(token);
    if (!/^[\w-]+$/.test(name) || !SAFE_VALUE.test(value)) {
      throw new Error(`token non valido: ${prefix}-${name}`);
    }
    return `  --${prefix}-${name}: ${value};`;
  });
}

export function render(tokens) {
  const { color, ...scales } = tokens;
  const base = Object.entries(scales)
    .filter(([group]) => !group.startsWith("$"))
    .flatMap(([group, entries]) => declarations(group, entries));
  const dark = declarations("color", color.dark).map((line) => `  ${line}`);
  return [
    "/* Generato da scripts/tokens.mjs a partire da doc/ux/tokens.json. Non modificare a mano. */",
    ":root {",
    ...declarations("color", color.light),
    ...base,
    "}",
    "",
    "@media (prefers-color-scheme: dark) {",
    "  :root {",
    ...dark,
    "  }",
    "}",
    "",
  ].join("\n");
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const expected = render(JSON.parse(readFileSync(SOURCE, "utf8")));
  if (process.argv.includes("--check")) {
    if (!existsSync(TARGET) || readFileSync(TARGET, "utf8") !== expected) {
      console.error("src/styles/tokens.css non coincide con doc/ux/tokens.json: pnpm tokens");
      process.exit(1);
    }
  } else {
    writeFileSync(TARGET, expected);
  }
}

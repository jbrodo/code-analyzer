// Raccoglie i file di licenza delle dipendenze di esecuzione della SPA (I-03) in <destinazione>/web/.
// Uso: node collect_web_licenses.mjs <cartella web/> <destinazione>
// Parte da `dependencies` di package.json e segue le loro `dependencies` in node_modules: un
// insieme che include tutto ciò che il bundle può contenere (e, per prudenza, qualcosa in più).
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const [web, out] = process.argv.slice(2);
if (!web || !out) {
  console.error("uso: collect_web_licenses.mjs <cartella web/> <destinazione>");
  process.exit(2);
}
const modules = join(web, "node_modules");
const root = JSON.parse(readFileSync(join(web, "package.json"), "utf8"));
const seen = new Map();

function find(name, from) {
  // risoluzione annidata come fa node: prima node_modules vicino, poi quello della radice
  for (const base of [join(from, "node_modules"), modules]) {
    const dir = join(base, name);
    if (existsSync(join(dir, "package.json"))) return dir;
  }
  return null;
}

function visit(name, from) {
  const dir = find(name, from);
  if (dir === null || seen.has(dir)) return;
  const pkg = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
  seen.set(dir, pkg);
  for (const dep of Object.keys(pkg.dependencies ?? {})) visit(dep, dir);
}

for (const dep of Object.keys(root.dependencies ?? {})) visit(dep, web);

const target = join(out, "web");
mkdirSync(target, { recursive: true });
const rows = [];
for (const [dir, pkg] of seen) {
  const safe = `${pkg.name.replace("@", "").replace("/", "__")}-${pkg.version}`;
  const files = readdirSync(dir).filter((f) => /^(licen[cs]e|copying|notice)/i.test(f));
  for (const file of files) {
    mkdirSync(join(target, safe), { recursive: true });
    cpSync(join(dir, file), join(target, safe, file));
  }
  rows.push(`${pkg.name}@${pkg.version}\t${files.length > 0 ? "testo copiato" : "NESSUN FILE DI LICENZA"}`);
}
writeFileSync(join(target, "INDEX.tsv"), rows.sort().join("\n") + "\n");
console.log(`${rows.length} pacchetti, ${rows.filter((r) => r.endsWith("NESSUN FILE DI LICENZA")).length} senza file di licenza`);

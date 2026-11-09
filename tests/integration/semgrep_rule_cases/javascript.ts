// Casi di prova delle regole Semgrep (dati, non codice da eseguire).
import { exec, execSync } from "child_process";
import crypto from "crypto";

// --- ca-js-command-injection
app.get("/a", (req, res) => {
  const dir = String(req.query.dir);
  // ruleid: ca-js-command-injection
  exec(`ls ${dir}`, () => {});
  // ruleid: ca-js-command-injection
  execSync("ls " + req.body.dir);
});
app.get("/b", (req, res) => {
  const fixed = "/tmp";
  // ok: ca-js-command-injection
  exec(`ls ${fixed}`, () => {});
  // ok: ca-js-command-injection
  exec(`ls ${shellEscape(req.query.dir)}`, () => {});
});

// --- ca-js-eval-dynamic
app.post("/c", (req, res) => {
  // ruleid: ca-js-eval-dynamic
  const r = eval(String(req.body.expression));
  // ruleid: ca-js-eval-dynamic
  const f = new Function("a", someString);
  // ok: ca-js-eval-dynamic
  const k = eval("1 + 1");
});

// --- ca-js-sql-injection
app.get("/d", (req, res) => {
  // ruleid: ca-js-sql-injection
  const query = "SELECT * FROM users WHERE name = '" + req.query.name + "'";
  (app.locals.db as { query: (sql: string) => unknown }).query(query);
  // ruleid: ca-js-sql-injection
  db.query("DELETE FROM t WHERE id = " + String(req.params.id));
  // ruleid: ca-js-sql-injection-template
  db.query(`SELECT * FROM users WHERE name = '${req.query.name}'`);
});
app.get("/e", (req, res) => {
  // ok: ca-js-sql-injection
  db.query("SELECT * FROM users WHERE name = $1", [req.query.name]);
  // ok: ca-js-sql-injection
  const msg = "Utente " + req.query.name;
  // ok: ca-js-sql-injection-template
  log(`Utente ${req.query.name}`);
  // ok: ca-js-sql-injection
  db.query("SELECT 1 WHERE x = " + localId);
});

// --- ca-js-reflected-xss
app.get("/f", (req, res) => {
  // ruleid: ca-js-reflected-xss
  res.send("<h1>Ciao " + req.query.name + "</h1>");
});
app.get("/g", (req, res) => {
  // ok: ca-js-reflected-xss
  res.send("<h1>Ciao " + escapeHtml(String(req.query.name)) + "</h1>");
  // ok: ca-js-reflected-xss
  res.send("<h1>Ciao</h1>");
});

// --- ca-js-weak-hash
export function d1(v: string): string {
  // ruleid: ca-js-weak-hash
  return crypto.createHash("md5").update(v).digest("hex");
}
export function d2(v: string): string {
  // ruleid: ca-js-weak-hash
  return crypto.createHash("sha1").update(v).digest("hex");
}
export function d3(v: string): string {
  // ok: ca-js-weak-hash
  return crypto.createHash("sha256").update(v).digest("hex");
}

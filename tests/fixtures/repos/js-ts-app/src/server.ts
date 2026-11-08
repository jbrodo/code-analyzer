import { exec } from "child_process";
import crypto from "crypto";
import express from "express";

const app = express();

// Problemi SAST noti della fixture F-03: non eseguire.

app.get("/list", (req, res) => {
  const dir = String(req.query.dir);
  exec(`ls ${dir}`, (_err, stdout) => {
    res.type("text").send(stdout);
  });
});

app.post("/calc", (req, res) => {
  const result = eval(String(req.body.expression));
  res.json({ result });
});

app.get("/user", (req, res, next) => {
  const query = "SELECT * FROM users WHERE name = '" + req.query.name + "'";
  (app.locals.db as { query: (sql: string) => unknown }).query(query);
  next();
});

app.get("/hello", (req, res) => {
  res.send("<h1>Ciao " + req.query.name + "</h1>");
});

export function digest(value: string): string {
  return crypto.createHash("md5").update(value).digest("hex");
}

app.listen(3000);

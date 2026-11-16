// @vitest-environment node
import { readFileSync } from "node:fs";

import { expect, test } from "vitest";

import { render } from "../scripts/tokens.mjs";

const tokens: unknown = JSON.parse(
  readFileSync(new URL("../../doc/ux/tokens.json", import.meta.url), "utf8"),
);
const css = readFileSync(new URL("./styles/tokens.css", import.meta.url), "utf8");
const base = readFileSync(new URL("./styles/base.css", import.meta.url), "utf8");

test("tokens.css è quello generato dai token di doc/ux", () => {
  expect(css).toBe(render(tokens));
});

test("i colori hanno un valore per tema", () => {
  const [light = "", dark = ""] = css.split("@media (prefers-color-scheme: dark)");
  const names = (text: string) => [...text.matchAll(/--color-[\w-]+/g)].map((m) => m[0]).sort();
  expect(names(light).length).toBeGreaterThan(0);
  expect(names(dark)).toEqual(names(light));
});

test("base.css usa solo proprietà definite dai token", () => {
  const defined = new Set([...css.matchAll(/(--[\w-]+):/g)].map((m) => m[1]));
  const used = [...base.matchAll(/var\((--[\w-]+)\)/g)].map((m) => m[1]);
  expect(used.length).toBeGreaterThan(0);
  expect(used.filter((name) => !defined.has(name))).toEqual([]);
});

test("base.css non contiene colori scritti a mano", () => {
  expect(base).not.toMatch(/#[0-9a-fA-F]{3,8}\b|rgb\(|hsl\(/);
});

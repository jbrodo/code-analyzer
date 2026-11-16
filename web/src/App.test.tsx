import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, test } from "vitest";

import { App } from "./App";

afterEach(cleanup);

test("la pagina ha un titolo e i punti di riferimento principali", () => {
  render(<App />);
  expect(screen.getByRole("banner")).toBeDefined();
  expect(screen.getByRole("main")).toBeDefined();
  expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("Code Analyzer");
});

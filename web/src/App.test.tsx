import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";

import { App } from "./App";

afterEach(cleanup);

test("la pagina ha un titolo e i punti di riferimento principali e, senza configurazione, un errore con codice", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("", { status: 404 }));
  render(<App />);
  expect(screen.getByRole("banner")).toBeDefined();
  expect(screen.getByRole("main")).toBeDefined();
  expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("Code Analyzer");
  expect(screen.getByText("Accesso in corso…")).toBeDefined();
  expect((await screen.findByRole("heading", { level: 2 })).textContent).toBe("Accesso non riuscito");
  expect(screen.getByText("config-unavailable")).toBeDefined();
  expect(screen.getByRole("button", { name: "Riprova" })).toBeDefined();
});

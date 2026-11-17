import { cleanup, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Route, Routes } from "react-router";
import { afterEach, expect, test, vi } from "vitest";

import { ApiError } from "@/api/client";
import type { Client, Schemas } from "@/api/client";
import { example } from "@/api/examples";
import { renderInSession } from "@/test-utils";
import { ScanPage } from "./ScanPage";
import { ScansPage } from "./ScansPage";

afterEach(cleanup);

const REPO = "0192f3a2-7c1e-7b55-9d0a-3f6c8e2b4a11";
const repo = { ...example("RepositorySummary"), current_scan: null };

function scan(n: number, over: Partial<Schemas["ScanSummary"]> = {}): Schemas["ScanSummary"] {
  return { ...example("ScanSummary"), id: `0192f3a2-7c1e-7b55-9d0a-${String(n).padStart(12, "0")}`, ...over };
}

function mountList(client: Partial<Client>) {
  return renderInSession(
    <Routes><Route path="/r/:repository/scans" element={<ScansPage />} /></Routes>,
    { getRepository: vi.fn(() => Promise.resolve(repo)), ...client },
    `/r/${REPO}/scans`,
  );
}

function mountScan(detail: Schemas["ScanDetail"] | Error) {
  return renderInSession(
    <Routes><Route path="/r/:repository/scans/:scan" element={<ScanPage />} /></Routes>,
    {
      getRepository: vi.fn(() => Promise.resolve(repo)),
      getScan: vi.fn(() => (detail instanceof Error ? Promise.reject(detail) : Promise.resolve(detail))),
    },
    `/r/${REPO}/scans/${scan(1).id}`,
  );
}

function detail(over: Partial<Schemas["ScanDetail"]> = {}, summary: Partial<Schemas["ScanSummary"]> = {}): Schemas["ScanDetail"] {
  return {
    summary: scan(1, summary),
    plugins: [
      { name: "bandit", version: "1.8.0", outcome: "ok", duration_seconds: 4.2, signature: "verified", isolation: "gvisor", digest: "sha256:x" },
      { name: "semgrep", version: "1.99", outcome: "failed", failure: "tempo scaduto", duration_seconds: 125, signature: "skipped", isolation: "hardened-container", digest: "sha256:y", feed: { origin: "cache", sync_failed: true, synced_at: "2026-11-10T08:00:00Z" } },
    ],
    warnings: [{ code: "feeds-stale", message: "I feed sono vecchi" }],
    gate: { mode: "all", effective_mode: "all" },
    ...over,
  };
}

test("l'elenco mostra tipo, ref, commit, inizio con la data esatta, durata e stato in parole", async () => {
  mountList({ listScans: vi.fn(() => Promise.resolve({ items: [scan(1), scan(2, { kind: "pr", pull_request: 12, status: "partial", ref: "refs/pull/12/merge" })], next_cursor: null })) });
  const table = await screen.findByRole("table", { name: /Scansioni di acme\/shop/ });
  const rows = within(table).getAllByRole("row").slice(1);
  expect(rows).toHaveLength(2);
  expect(within(rows[0] as HTMLElement).getByText("Completa", { selector: "td" })).toBeDefined();
  expect(within(rows[1] as HTMLElement).getByRole("link", { name: "PR #12" }).getAttribute("href")).toBe(`/r/${REPO}/scans/${scan(2).id}`);
  expect(within(rows[1] as HTMLElement).getByText("Parziale")).toBeDefined();
  expect(rows[0]?.querySelector("time")?.getAttribute("datetime")).toBe(scan(1).started_at); // S4
  expect(document.title).toBe("Scansioni · acme/shop · Code Analyzer");
});

test("Carica altri usa il cursore; senza scansioni dice come riceverne; un errore ha il codice", async () => {
  const user = userEvent.setup();
  const listScans = vi.fn().mockResolvedValueOnce({ items: [scan(1)], next_cursor: "c1" }).mockResolvedValueOnce({ items: [scan(2, { kind: "pr", pull_request: 3 })], next_cursor: null });
  mountList({ listScans });
  await user.click(await screen.findByRole("button", { name: "Carica altri" }));
  await screen.findByRole("link", { name: "PR #3" });
  expect(listScans.mock.calls[1]?.[1]).toMatchObject({ cursor: "c1" });
  cleanup();
  mountList({ listScans: vi.fn(() => Promise.resolve({ items: [], next_cursor: null })) });
  expect(await screen.findByText("code-analyzer upload")).toBeDefined();
  cleanup();
  mountList({ listScans: vi.fn(() => Promise.reject(new ApiError(500, "internal-error", null))) });
  expect((await screen.findByRole("alert")).textContent).toContain("internal-error");
});

test("una scansione parziale lo dice in cima con i plugin falliti e cosa comporta", async () => {
  mountScan(detail({}, { status: "partial" }));
  const banner = await screen.findByText("Scansione parziale.");
  expect(banner.parentElement?.textContent).toContain("Plugin non riusciti: semgrep");
  expect(banner.parentElement?.textContent).toContain("Nessun finding è stato segnato come risolto");
  const main = screen.getByRole("main");
  expect(main.querySelector(".banner")).toBe(main.querySelector("h1 ~ .banner")); // sta prima del riepilogo
  expect(screen.getByRole("heading", { level: 2, name: "Riepilogo" })).toBeDefined();
});

test("i plugin sono una tabella con esito, firma e isolamento a parole e lo snapshot dei feed con la data", async () => {
  mountScan(detail());
  const table = await screen.findByRole("table", { name: "Plugin della scansione" });
  const semgrep = within(table).getByRole("row", { name: /semgrep/ });
  for (const text of ["Fallito", "tempo scaduto", "Non verificata", "Contenitore rinforzato", "2 min 5 s"]) {
    expect(within(semgrep).getByText(new RegExp(text))).toBeDefined();
  }
  expect(semgrep.textContent).toContain("sincronizzazione fallita");
  expect(semgrep.querySelector("time")?.getAttribute("datetime")).toBe("2026-11-10T08:00:00Z");
  expect(within(within(table).getByRole("row", { name: /bandit/ })).getByText("Riuscito")).toBeDefined();
});

test("gli avvisi sono un elenco, uno per riga, col codice", async () => {
  mountScan(detail());
  const item = (await screen.findByText("I feed sono vecchi", { exact: false })).closest("li");
  expect(item?.querySelector("code")?.textContent).toBe("feeds-stale");
  cleanup();
  mountScan(detail({ warnings: [] }));
  expect(await screen.findByText("Nessun avviso.")).toBeDefined();
});

test("una PR mostra nuovi, esistenti e risolti e rimanda alla lista dei nuovi di quella scansione", async () => {
  const baseline = { status: "valid" as const, source: "ci-artifact" as const, commit: "b".repeat(40), new: 2, existing: 5, not_evaluated: 1, resolved: [{ fingerprint: "sha256:" + "c".repeat(64), rule_id: "B101", title: "Uso di assert" }] };
  mountScan(detail({ baseline }, { kind: "pr", pull_request: 7 }));
  const section = (await screen.findByRole("heading", { name: "Rispetto al branch base" })).closest("section") as HTMLElement;
  expect(section.textContent).toContain("artefatto della CI");
  expect(section.textContent).toContain("Non valutati");
  expect(within(section).getByText("Uso di assert")).toBeDefined();
  const link = within(section).getByRole("link", { name: /2 finding nuovi/ });
  expect(link.getAttribute("href")).toBe(`/r/${REPO}?scan=${scan(1).id}&new=true&status=any`);
});

test("una scansione completa non ha la sezione della baseline; una inesistente è un avviso", async () => {
  mountScan(detail());
  await screen.findByRole("table", { name: "Plugin della scansione" });
  expect(screen.queryByRole("heading", { name: "Rispetto al branch base" })).toBeNull();
  cleanup();
  mountScan(new ApiError(404, "not-found", null));
  await waitFor(() => { expect(screen.getByRole("alert").textContent).toContain("Scansione non trovata."); });
});

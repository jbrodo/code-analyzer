import { cleanup, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Route, Routes, useLocation } from "react-router";
import { afterEach, expect, test, vi } from "vitest";

import { ApiError } from "@/api/client";
import type { Client, Schemas } from "@/api/client";
import { example } from "@/api/examples";
import { FindingsPage } from "@/features/findings/FindingsPage";
import { renderInSession } from "@/test-utils";
import { FindingPanel } from "./FindingPanel";

afterEach(cleanup);

const REPO = "0192f3a2-7c1e-7b55-9d0a-3f6c8e2b4a11";
const FID = "0192f3a2-7c1e-7b55-9d0a-000000000001";

type Detail = Schemas["FindingDetail"];

function score(variant: "A" | "B", over: Partial<Schemas["ImpactFactors"]> = {}, level: Schemas["Level"] = "medio", value = 18): Schemas["VariantScore"] {
  return {
    variant,
    score: value,
    level,
    impact: {
      g: 0.75, p: 0.4, e: 0.6, c: 1, variant,
      evidence: { g: { rule: "severity", source: "cvss" }, p: { rule: "epss", epss: 0.12 }, e: { rule: "reach" }, c: { rule: "tier", tier: 2 } },
      ...over,
    },
  };
}

function detail(over: Partial<Detail> = {}, finding: Partial<Schemas["Finding"]> = {}): Detail {
  return {
    finding: {
      id: FID, fingerprint: "sha256:" + "a".repeat(64), category: "sast", rule_id: "regola-1", tool: "bandit", tools: ["bandit"],
      title: "Query SQL costruita con una stringa", message: "m", location: { repository: "shop", path: "app/db.py", start_line: 12 },
      first_seen: "2026-06-01T12:00:00Z", last_seen: "2026-11-17T12:00:00Z", status: "aperto", level: "alto", level_source: "tool_severity",
      ...finding,
    },
    occurrence: { scan_id: example("ScanSummary").id, commit: "c0ffee" + "0".repeat(34), variant_scores: [score("A"), score("B")] },
    exceptions: [],
    events: [],
    ...over,
  };
}

function Where() {
  const where = useLocation();
  return <span data-testid="where">{where.pathname + where.search}</span>;
}

function mount(data: Detail | Error, route = `/r/${REPO}/f/${FID}`) {
  const client = {
    getFinding: vi.fn(() => (data instanceof Error ? Promise.reject(data) : Promise.resolve(data))),
    getRepository: vi.fn(() => Promise.resolve({ ...example("RepositorySummary"), current_scan: { ...example("ScanSummary"), status: "complete" } })),
    listFindings: vi.fn(() => Promise.resolve({ items: [{ ...example("FindingListItem"), id: FID, title: "Query SQL costruita con una stringa" }], total: 1, total_new: 0, next_cursor: null })),
  } as unknown as Client;
  return renderInSession(
    <>
      <Routes>
        <Route path="/r/:repository" element={<FindingsPage />}>
          <Route path="f/:finding" element={<FindingPanel />} />
        </Route>
      </Routes>
      <Where />
    </>,
    client,
    route,
  );
}

test("il pannello è una regione col titolo del finding, con le sezioni nell'ordine di U-01", async () => {
  mount(detail());
  const panel = await screen.findByRole("complementary", { name: "Query SQL costruita con una stringa" });
  const sections = within(panel).getAllByRole("heading", { level: 3 }).map((h) => h.textContent);
  expect(sections).toEqual(["Come risolvere", "Dove", "Perché questo livello", "Stato e storia"]);
  expect(within(panel).getByRole("heading", { level: 2 }).textContent).toBe("Query SQL costruita con una stringa");
  await waitFor(() => { expect(document.activeElement?.id).toBe("panel-title"); }); // D2: il fuoco va al titolo
});

test("senza passi di correzione lo dice, con la regola; con i passi li rende come testo", async () => {
  mount(detail());
  expect(await screen.findByText("Questo strumento non fornisce indicazioni di correzione.")).toBeDefined();
  cleanup();
  const hostile = '<a href="https://evil.example">clicca</a> <img src=x onerror=alert(1)>';
  mount(detail({}, { remediation: { text: hostile, source: "tool", references: ["https://docs.example/rule"] } }));
  const text = await screen.findByText(hostile);
  expect(text.querySelector("a, img")).toBeNull();
  expect(screen.getByText("Indicazione dello strumento")).toBeDefined();
  const reference = screen.getByText("https://docs.example/rule");
  expect(reference.closest("a")).toBeNull(); // un riferimento del report non è un collegamento attivo
});

test("le due varianti hanno la stessa struttura, in ordine fisso, con la formula e senza giudizi", async () => {
  mount(detail({ occurrence: { scan_id: "s", commit: "c".repeat(40), variant_scores: [score("B", {}, "alto", 30), score("A", {}, "medio", 18)] } }));
  await screen.findByRole("heading", { name: "Punteggi in ombra" });
  const titles = screen.getAllByRole("heading", { level: 4 }).map((h) => h.textContent).filter((t) => t.startsWith("Variante"));
  expect(titles).toEqual(["Variante A", "Variante B"]); // l'ordine non segue i valori
  const tables = screen.getAllByRole("table", { name: /Fattori della variante/ });
  expect(tables.map((t) => within(t).getAllByRole("row").length)).toEqual([5, 5]);
  const a = tables[0];
  expect(a && within(a).getByText("Gravità (G)")).toBeDefined();
  expect(a && within(a).getAllByText("0,75").length).toBeGreaterThan(0);
  const formulas = screen.getAllByText(/100 × 0,75 × 0,40 × 0,60 × 1,00 =/).map((f) => f.textContent);
  expect(formulas[0]).toContain("18,00"); // A
  expect(formulas[1]).toContain("30,00"); // B
  expect(screen.getByText("Le due varianti danno livelli diversi: A medio, B alto.")).toBeDefined();
  expect(screen.getByText("Non decidono il livello. Servono al confronto delle due varianti.")).toBeDefined();
  const section = screen.getByRole("heading", { name: "Perché questo livello" }).closest("section");
  expect(section?.textContent).not.toMatch(/migliore|peggiore|scarto/i);
});

test.each(["variante-b-non-definita", "variante-b-non-configurata"])("la variante B senza parametri (%s) dichiara il ripiego e le due coincidono", async (code) => {
  const fallback = { fallbacks: [code] };
  const a = score("A");
  const b = score("B", { evidence: { ...score("B").impact.evidence, ...fallback } });
  mount(detail({ occurrence: { scan_id: "s", commit: "c".repeat(40), variant_scores: [a, b] } }));
  expect(await screen.findByText("Variante B non configurata per questa categoria: coincide con A.")).toBeDefined();
  expect(screen.getByText("Le due varianti coincidono.")).toBeDefined();
  expect(screen.getAllByText(code).length).toBeGreaterThan(0);
});

test("l'origine del livello è in parole e i valori dell'evidenza sono testo", async () => {
  mount(detail({}, { level: "critico", level_source: "override" }));
  expect(await screen.findByText("Livello alzato da un override")).toBeDefined();
  cleanup();
  const evil = "<script>window.__x=1</script>";
  mount(detail({ occurrence: { scan_id: "s", commit: "c".repeat(40), variant_scores: [score("A", { evidence: { g: { rule: evil } } }), score("B")] } }));
  const cell = await screen.findByText(evil);
  expect(cell.querySelector("script")).toBeNull();
});

test("le eccezioni delle due origini sono distinte e quella del repository è non verificata", async () => {
  const exceptions: Schemas["ExceptionRecord"][] = [
    { id: "1", origin: "server", reason: "migrazione", expires: "2027-06-30", approved_by: "https://idp|ada", approved_by_verified: true },
    { id: "2", origin: "repository", reason: "dal file", expires: "2027-06-30", approved_by: "Chiunque", approved_by_verified: false },
  ];
  mount(detail({ exceptions }));
  expect(await screen.findByText(/Accettato da https:\/\/idp\|ada fino al/)).toBeDefined();
  expect(screen.getByText(/Approvatore dichiarato: Chiunque, non verificato/)).toBeDefined();
  expect(screen.getByText("Motivazione: migrazione")).toBeDefined();
});

test("il registro delle modifiche è un elenco ordinato con le date in time", async () => {
  const events = [{ at: "2026-11-17T12:00:00Z", actor: "https://idp|ada", action: "set-status", from_state: "aperto" as const, to_state: "in_corso" as const, reason: "preso" }];
  mount(detail({ events }));
  const item = (await screen.findByText(/set-status/)).closest("li");
  expect(item?.querySelector("time")?.getAttribute("datetime")).toBe("2026-11-17T12:00:00Z");
  expect(item?.textContent).toContain("Aperto → In corso");
  expect(item?.closest("ol")).not.toBeNull();
});

test("Esc chiude il pannello, tiene i filtri e riporta il fuoco sulla riga di partenza", async () => {
  const user = userEvent.setup();
  mount(detail(), `/r/${REPO}/f/${FID}?level=alto`);
  await screen.findByRole("complementary");
  await user.keyboard("{Escape}");
  await waitFor(() => { expect(screen.getByTestId("where").textContent).toBe(`/r/${REPO}?level=alto`); });
  await waitFor(() => { expect(document.activeElement?.getAttribute("href")).toContain(FID); });
  expect(screen.queryByRole("complementary")).toBeNull();
});

test("un finding che non esiste più è un avviso, non una pagina vuota", async () => {
  mount(new ApiError(404, "not-found", null));
  const alert = await screen.findByRole("alert");
  expect(alert.textContent).toContain("Finding non trovato o non più presente.");
  expect(within(alert).getByRole("button", { name: "Torna alla lista" })).toBeDefined();
});

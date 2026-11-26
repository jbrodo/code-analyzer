/** W-08: ogni vista in ogni stato di U-01, con i controlli automatici di U-03 (axe) e i criteri A che
 * axe non copre. Un criterio A senza test è un difetto del task. */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { cleanup, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Route, Routes } from "react-router";
import { afterEach, describe, expect, test, vi } from "vitest";

import { ApiError } from "@/api/client";
import type { Client, Schemas } from "@/api/client";
import { violations } from "@/a11y";
import { FindingPanel } from "@/features/finding/FindingPanel";
import { FindingsPage } from "@/features/findings/FindingsPage";
import { RepositoriesPage } from "@/features/repositories/RepositoriesPage";
import { ScanPage } from "@/features/scans/ScanPage";
import { ScansPage } from "@/features/scans/ScansPage";
import { REPO, detail, item, page, repository, scan, scanDetail, uuid } from "@/fixtures";
import { Shell } from "@/layout/Shell";
import { renderInSession } from "@/test-utils";

afterEach(cleanup);

const forever = <T,>() => new Promise<T>(() => undefined);
const approver: Schemas["Me"] = { issuer: "https://idp", subject: "u1", name: "Ada", tenant: "acme", roles: ["lettore", "triage", "approvatore"] };
const exceptions: Schemas["ExceptionRecord"][] = [
  { id: "1", origin: "server", reason: "migrazione", expires: "2999-06-30", approved_by: "https://idp|ada", approved_by_verified: true },
  { id: "2", origin: "repository", reason: "dal file", expires: "2999-06-30", approved_by: "Chiunque", approved_by_verified: false },
];

function client(over: Partial<Record<keyof Client, unknown>> = {}): Partial<Client> {
  return {
    getRepository: vi.fn(() => Promise.resolve(repository())),
    listRepositories: vi.fn(() => Promise.resolve({ items: [repository()], next_cursor: null })),
    listFindings: vi.fn(() => Promise.resolve(page([item(1, { new: true }), item(2, { level: "critico" }), item(3, { status: "accettato", exception_origin: "server", level: "basso" })], null, 1))),
    getFinding: vi.fn(() => Promise.resolve(detail({ exceptions, events: [{ at: "2026-11-17T12:00:00Z", actor: "ada", action: "set-status", from_state: "aperto", to_state: "in_corso", reason: "preso" }] }))),
    listScans: vi.fn(() => Promise.resolve({ items: [scan(1), scan(2, { kind: "pr", pull_request: 4, status: "partial" })], next_cursor: null })),
    getScan: vi.fn(() => Promise.resolve(scanDetail())),
    patchFinding: vi.fn(() => Promise.resolve(detail())),
    me: vi.fn(() => Promise.resolve(approver)),
    ...over,
  } as Partial<Client>;
}

function list(over: Partial<Record<keyof Client, unknown>> = {}, route = `/r/${REPO}`) {
  return renderInSession(
    <Routes>
      <Route path="/r/:repository" element={<FindingsPage />}>
        <Route path="f/:finding" element={<FindingPanel />} />
      </Route>
    </Routes>,
    client(over), route, approver,
  );
}

const states: [string, () => void, () => Promise<unknown>][] = [
  ["lista: caricamento", () => list({ listFindings: () => forever() }), () => screen.findByRole("table")],
  ["lista: con finding", () => list(), () => screen.findByText("Problema 1")],
  ["lista: filtri attivi", () => list({}, `/r/${REPO}?level=alto&q=sql&sort=path`), () => screen.findByRole("button", { name: /Rimuovi filtro livello Alto/ })],
  ["lista: vuota per i filtri", () => list({ listFindings: () => Promise.resolve(page([])) }, `/r/${REPO}?level=critico`), () => screen.findByText(/Nessun finding con questi filtri/)],
  ["lista: nessun finding", () => list({ listFindings: () => Promise.resolve(page([])) }), () => screen.findByText("Nessun finding aperto.")],
  ["lista: nessuna scansione", () => list({ getRepository: () => Promise.resolve(repository({ current_scan: null })), listFindings: () => Promise.resolve(page([])) }), () => screen.findByText(/Nessuna scansione ricevuta/)],
  ["lista: errore", () => list({ listFindings: () => Promise.reject(new ApiError(500, "internal-error", null)) }), () => screen.findByRole("alert")],
  ["lista: repository non trovato", () => list({ getRepository: () => Promise.reject(new ApiError(404, "not-found", null)) }), () => screen.findByRole("alert")],
  ["lista: scansione parziale", () => list({ getRepository: () => Promise.resolve(repository({ current_scan: scan(1, { status: "partial" }) })), getScan: () => Promise.resolve(scanDetail({}, { status: "partial" })) }), () => screen.findByText(/1 plugin non riuscito/)],
  ["dettaglio: caricamento", () => list({ getFinding: () => forever() }, `/r/${REPO}/f/${uuid(1)}`), () => screen.findByRole("complementary")],
  ["dettaglio: con azioni da approvatore", () => list({}, `/r/${REPO}/f/${uuid(1)}`), () => screen.findByRole("region", { name: "Azioni" })],
  ["dettaglio: errore", () => list({ getFinding: () => Promise.reject(new ApiError(404, "not-found", null)) }, `/r/${REPO}/f/${uuid(1)}`), () => screen.findByText(/non trovato o non più presente/)],
  ["scansioni: elenco", () => renderInSession(<Routes><Route path="/r/:repository/scans" element={<ScansPage />} /></Routes>, client(), `/r/${REPO}/scans`), () => screen.findByRole("link", { name: "PR #4" })],
  ["scansioni: vuoto", () => renderInSession(<Routes><Route path="/r/:repository/scans" element={<ScansPage />} /></Routes>, client({ listScans: () => Promise.resolve({ items: [], next_cursor: null }) }), `/r/${REPO}/scans`), () => screen.findByText("code-analyzer upload")],
  ["scansione: parziale con plugin e avvisi", () => renderInSession(<Routes><Route path="/r/:repository/scans/:scan" element={<ScanPage />} /></Routes>, client({ getScan: () => Promise.resolve(scanDetail({}, { status: "partial" })) }), `/r/${REPO}/scans/${uuid(1)}`), () => screen.findByText("Scansione parziale.")],
  ["scansione: PR con baseline", () => renderInSession(<Routes><Route path="/r/:repository/scans/:scan" element={<ScanPage />} /></Routes>, client({ getScan: () => Promise.resolve(scanDetail({ baseline: { status: "valid", source: "ci-artifact", new: 2, existing: 3, not_evaluated: 0, resolved: [] } }, { kind: "pr", pull_request: 4 })) }), `/r/${REPO}/scans/${uuid(1)}`), () => screen.findByRole("heading", { name: "Rispetto al branch base" })],
  ["repository: elenco", () => renderInSession(<RepositoriesPage />, client({ listRepositories: () => Promise.resolve({ items: [repository(), repository({ id: uuid(9), name: "acme/altro", current_scan: null })], next_cursor: null }) })), () => screen.findByRole("link", { name: "acme/altro" })],
  ["repository: vuoto", () => renderInSession(<RepositoriesPage />, client({ listRepositories: () => Promise.resolve({ items: [], next_cursor: null }) })), () => screen.findByText("Nessun repository.")],
  ["repository: errore", () => renderInSession(<RepositoriesPage />, client({ listRepositories: () => Promise.reject(new ApiError(500, "internal-error", null)) })), () => screen.findByRole("alert")],
];

describe("axe su ogni vista e stato di U-01", () => {
  test.each(states)("%s", async (_name, mount, ready) => {
    mount();
    await ready();
    expect(await violations()).toEqual([]);
  });
});

test("il controllo trova davvero i difetti: immagine senza testo alternativo e pulsante senza nome", async () => {
  const probe = document.createElement("div");
  probe.innerHTML = '<main><h1>x</h1><img src="a.png"><button></button></main>';
  document.body.append(probe);
  const found = await violations(probe);
  probe.remove();
  expect(found.some((v) => v.startsWith("image-alt"))).toBe(true);
  expect(found.some((v) => v.startsWith("button-name"))).toBe(true);
});

describe("dialoghi aperti", () => {
  test("falso positivo, con l'errore di validazione", async () => {
    const user = userEvent.setup();
    list({}, `/r/${REPO}/f/${uuid(1)}`);
    await user.click(await screen.findByRole("button", { name: "Segna come falso positivo" }));
    const dialog = await screen.findByRole("dialog");
    await user.click(within(dialog).getByRole("button", { name: "Segna come falso positivo" }));
    expect(await violations()).toEqual([]);
  });
  test("eccezione, con il frammento e l'errore", async () => {
    const user = userEvent.setup();
    list({}, `/r/${REPO}/f/${uuid(1)}`);
    await user.click(await screen.findByRole("button", { name: "Accetta con eccezione" }));
    const dialog = await screen.findByRole("dialog");
    await user.type(within(dialog).getByLabelText(/Scadenza/), "domani");
    await user.click(within(dialog).getAllByRole("button", { name: "Accetta con eccezione" }).at(-1) as HTMLElement);
    expect(await violations()).toEqual([]);
  });
  test("menu di un filtro aperto", async () => {
    const user = userEvent.setup();
    list();
    await user.click(await screen.findByRole("button", { name: "Filtro Categoria" }));
    await screen.findByRole("menu");
    expect(await violations()).toEqual([]);
  });
});

describe("criteri A che axe non copre", () => {
  test("G1/G2: ogni pagina ha un solo h1 col nome del repository, i punti di riferimento e il salto al contenuto", async () => {
    renderInSession(<Shell />, client(), `/r/${REPO}`, approver);
    await screen.findByText("Problema 1");
    expect(screen.getAllByRole("heading", { level: 1 })).toHaveLength(1);
    expect(screen.getByRole("heading", { level: 1 }).textContent).toContain("acme/shop");
    expect(screen.getByRole("banner")).toBeDefined();
    expect(screen.getAllByRole("main")).toHaveLength(1);
    const skip = screen.getByRole("link", { name: "Vai al contenuto" });
    expect(skip.getAttribute("href")).toBe("#contenuto");
    expect(document.getElementById("contenuto")).not.toBeNull();
    expect(readFileSync(resolve(process.cwd(), "index.html"), "utf8")).toContain('<html lang="it">'); // G13
    await waitFor(() => { expect(document.title).toBe("Finding · acme/shop · Code Analyzer"); });
    expect(await violations()).toEqual([]);
  });

  test("G2: «Vai al contenuto» è il primo elemento raggiungibile con Tab", async () => {
    const user = userEvent.setup();
    renderInSession(<Shell />, client(), `/r/${REPO}`, approver);
    await screen.findByText("Problema 1");
    await user.tab();
    expect(document.activeElement?.textContent).toBe("Vai al contenuto");
  });

  test("L1/L2/L5/L6/L8: tabella con didascalia, un solo controllo per riga, aria-sort, livello a parole e percorso completo", async () => {
    list({ listFindings: () => Promise.resolve(page([item(1, { path: "a/molto/lunga/cartella/di/prova/che/si/tronca/nel/mezzo/file.py", start_line: 7 })])) }, `/r/${REPO}?sort=path`);
    const table = await screen.findByRole("table", { name: /Finding di acme\/shop/ });
    for (const th of within(table).getAllByRole("columnheader")) expect(th.getAttribute("scope")).toBe("col");
    const row = within(table).getAllByRole("row")[1] as HTMLElement;
    expect(within(row).getAllByRole("link")).toHaveLength(1);
    expect(within(row).getByRole("link").getAttribute("aria-label")).toMatch(/^Alto: /);
    expect(within(table).getByRole("columnheader", { name: "Posizione" }).getAttribute("aria-sort")).toBe("ascending");
    expect(row.textContent).toContain("a/molto/lunga/cartella/di/prova/che/si/tronca/nel/mezzo/file.py:7"); // il valore completo, non solo il troncato
  });

  test("L12/L13: caricamento con aria-busy e righe segnaposto nascoste; errore con role alert", async () => {
    list({ listFindings: () => forever() });
    const table = await screen.findByRole("table");
    expect(table.getAttribute("aria-busy")).toBe("true");
    expect(table.querySelectorAll("tr[aria-hidden='true']").length).toBeGreaterThan(0);
  });

  test("L10: cambiare un filtro non sposta il fuoco e annuncia il numero dei risultati", async () => {
    const user = userEvent.setup();
    list();
    const toggle = await screen.findByRole("checkbox", { name: /Solo nuovi/ });
    await user.click(toggle);
    await waitFor(() => { expect(document.activeElement).toBe(toggle); });
    await waitFor(() => { expect(screen.getByRole("status").textContent).toMatch(/\d+ finding con i filtri attivi/); });
  });

  test("L4: le scorciatoie a un carattere non fanno nulla fuori dalla tabella e dentro i campi", async () => {
    const user = userEvent.setup();
    list();
    const search = await screen.findByRole("searchbox");
    await user.click(search);
    await user.keyboard("jk/");
    expect((search as HTMLInputElement).value).toBe("jk/");
    (screen.getByRole("button", { name: "Filtro Livello" })).focus();
    await user.keyboard("j");
    expect(document.activeElement?.textContent).toContain("Livello");
  });

  test("D1/D3: il pannello è una regione col titolo, non un dialogo, con le intestazioni in ordine", async () => {
    list({}, `/r/${REPO}/f/${uuid(1)}`);
    const panel = await screen.findByRole("complementary", { name: "Query SQL costruita con una stringa" });
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.getByRole("table", { name: /Finding di/ })).toBeDefined(); // la lista resta raggiungibile
    const levels = within(panel).getAllByRole("heading").map((h) => Number(h.tagName.slice(1)));
    for (let i = 1; i < levels.length; i++) expect((levels[i] as number) - (levels[i - 1] as number)).toBeLessThanOrEqual(1);
  });

  test("D4/D5: i fattori sono una tabella con le etichette per esteso; il registro è un elenco ordinato con time", async () => {
    list({}, `/r/${REPO}/f/${uuid(1)}`);
    const factors = await screen.findAllByRole("table", { name: /Fattori della variante/ });
    expect(within(factors[0] as HTMLElement).getByRole("rowheader", { name: "Esposizione (E)" })).toBeDefined();
    const log = screen.getByText(/set-status/).closest("ol");
    expect(log?.querySelector("time")).not.toBeNull();
  });

  test("D6: l'azione oltre il ruolo è raggiungibile e dichiara il motivo nel nome descrittivo", async () => {
    renderInSession(
      <Routes><Route path="/r/:repository" element={<FindingsPage />}><Route path="f/:finding" element={<FindingPanel />} /></Route></Routes>,
      client(), `/r/${REPO}/f/${uuid(1)}`, { ...approver, roles: ["lettore", "triage"] },
    );
    const button = await screen.findByRole("button", { name: "Accetta con eccezione" });
    expect(button.getAttribute("aria-disabled")).toBe("true");
    expect(document.getElementById(button.getAttribute("aria-describedby") ?? "")?.textContent).toBe("Serve il ruolo approvatore.");
    expect(await violations()).toEqual([]);
  });

  test("T1/T3: il dialogo ha nome e descrizione, il fuoco entra nel primo campo e le etichette dicono «obbligatorio»", async () => {
    const user = userEvent.setup();
    list({}, `/r/${REPO}/f/${uuid(1)}`);
    await user.click(await screen.findByRole("button", { name: "Accetta con eccezione" }));
    const dialog = await screen.findByRole("dialog", { name: "Accetta con eccezione" });
    expect(dialog.getAttribute("aria-describedby")).toBeTruthy();
    await waitFor(() => { expect(dialog.contains(document.activeElement)).toBe(true); });
    expect(within(dialog).getByLabelText("Motivazione (obbligatorio)")).toBeDefined();
    expect(within(dialog).getByLabelText("Scadenza (obbligatorio)")).toBeDefined();
  });

  test("S1/S2/S4: tabelle delle scansioni con didascalia, parole per stato ed esito, data esatta in time", async () => {
    renderInSession(<Routes><Route path="/r/:repository/scans/:scan" element={<ScanPage />} /></Routes>, client(), `/r/${REPO}/scans/${uuid(1)}`);
    const plugins = await screen.findByRole("table", { name: "Plugin della scansione" });
    expect(within(plugins).getByText("Riuscito")).toBeDefined();
    expect(within(plugins).getByText("Fallito")).toBeDefined();
    const when = document.querySelector("time");
    expect(when?.getAttribute("datetime")).toBe(scan(1).started_at);
    expect(when?.querySelector(".visually-hidden")?.textContent).toMatch(/\d{4}/); // la data esatta accanto al tempo relativo
  });
});

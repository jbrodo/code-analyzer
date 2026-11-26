import { cleanup, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Route, Routes, useLocation } from "react-router";
import { afterEach, expect, test, vi } from "vitest";

import { ApiError } from "@/api/client";
import type { Client, Schemas } from "@/api/client";
import { example } from "@/api/examples";
import { renderInSession } from "@/test-utils";
import { FindingsPage } from "./FindingsPage";

afterEach(cleanup);

type Item = Schemas["FindingListItem"];
function at<T>(list: readonly T[], index: number): T {
  const found = list[index];
  if (found === undefined) throw new Error(`manca l'elemento ${String(index)}`);
  return found;
}

const REPO = "0192f3a2-7c1e-7b55-9d0a-3f6c8e2b4a11";

function item(n: number, over: Partial<Item> = {}): Item {
  return {
    ...example("FindingListItem"),
    id: `0192f3a2-7c1e-7b55-9d0a-${String(n).padStart(12, "0")}`,
    title: `Problema ${String(n)}`,
    rule_id: `regola-${String(n)}`,
    ...over,
  };
}

function repo(over: Partial<Schemas["RepositorySummary"]> = {}): Schemas["RepositorySummary"] {
  return {
    ...example("RepositorySummary"),
    current_scan: { ...example("ScanSummary"), status: "complete" },
    ...over,
  };
}

function fakeClient(page: Schemas["FindingPage"], over: Partial<Client> = {}) {
  return {
    getRepository: vi.fn(() => Promise.resolve(repo())),
    listFindings: vi.fn(() => Promise.resolve(page)),
    getScan: vi.fn(),
    ...over,
  } as unknown as Client & { listFindings: ReturnType<typeof vi.fn>; getRepository: ReturnType<typeof vi.fn> };
}

function Where() {
  const where = useLocation();
  return <span data-testid="where">{where.pathname + where.search}</span>;
}

function mount(client: Partial<Client>, route = `/r/${REPO}`) {
  return renderInSession(
    <>
      <Routes>
        <Route path="/r/:repository" element={<FindingsPage />}>
          <Route path="f/:finding" element={null} />
        </Route>
      </Routes>
      <Where />
    </>,
    client,
    route,
  );
}

const page = (items: Item[], total = items.length, next: string | null = null, totalNew = 0): Schemas["FindingPage"] => ({
  items, total, total_new: totalNew, next_cursor: next,
});

test("la lista mostra una riga per finding, con la parola del livello e il titolo come collegamento", async () => {
  const client = fakeClient(page([item(1, { level: "critico", new: true }), item(2, { level: "basso", new: false })], 2, null, 1));
  mount(client);
  const table = await screen.findByRole("table");
  const rows = within(table).getAllByRole("row").slice(1);
  expect(rows).toHaveLength(2);
  expect(within(at(rows, 0)).getByText("Critico")).toBeDefined();
  expect(within(at(rows, 0)).getByText("Nuovo")).toBeDefined();
  expect(within(at(rows, 1)).queryByText("Nuovo")).toBeNull();
  const link = within(at(rows, 0)).getByRole("link");
  expect(link.getAttribute("aria-label")).toBe("Critico: Problema 1");
  expect(screen.getByText("2 finding")).toBeDefined();
  expect(screen.getByRole("heading", { level: 1 }).textContent).toContain("acme/shop");
  // il titolo arriva da un effetto, che può girare dopo che il contenuto è già visibile
  await waitFor(() => { expect(document.title).toBe("Finding · acme/shop · Code Analyzer"); });
});

test("il predefinito chiede aperti e in corso e lo dice tra i filtri", async () => {
  const client = fakeClient(page([item(1)]));
  mount(client);
  await screen.findByRole("table");
  const query = client.listFindings.mock.calls[0]?.[1] as Record<string, unknown>;
  expect(query.status).toEqual(["aperto", "in_corso"]);
  expect(query.sort).toBe("impact");
  expect(query.limit).toBe(50);
});

test("il contenuto del report è testo: nessun markup entra nel documento", async () => {
  const hostile = '<img src=x onerror="window.__pwned=1"><b>grassetto</b>';
  mount(fakeClient(page([item(1, { title: hostile, rule_id: "<script>1</script>", path: "<a href=//evil>x</a>.py" })])));
  const table = await screen.findByRole("table");
  expect(table.querySelector("img, b, script, a[href*='evil']")).toBeNull();
  expect(within(table).getByText(hostile)).toBeDefined();
  expect((window as unknown as { __pwned?: number }).__pwned).toBeUndefined();
});

test("un filtro cambia l'indirizzo e la richiesta; un chip lo toglie e Azzera filtri li toglie tutti", async () => {
  const user = userEvent.setup();
  const client = fakeClient(page([item(1)]));
  mount(client);
  await screen.findByRole("table");
  await user.click(screen.getByRole("button", { name: "Filtro Livello" }));
  await user.click(await screen.findByRole("menuitemcheckbox", { name: "Critico" }));
  await user.keyboard("{Escape}");
  await waitFor(() => { expect(screen.getByTestId("where").textContent).toBe(`/r/${REPO}?level=critico`); });
  const last = client.listFindings.mock.calls.at(-1)?.[1] as Record<string, unknown>;
  expect(last.level).toEqual(["critico"]);
  await user.click(screen.getByRole("button", { name: "Rimuovi filtro livello Critico" }));
  await waitFor(() => { expect(screen.getByTestId("where").textContent).toBe(`/r/${REPO}`); });
});

test("i filtri nell'indirizzo riaprono la stessa vista, ignorando i valori sconosciuti", async () => {
  const client = fakeClient(page([item(1)]));
  mount(client, `/r/${REPO}?level=alto&level=INVENTATO&status=any&new=true&sort=path&q=sql`);
  await screen.findByRole("table");
  const query = client.listFindings.mock.calls[0]?.[1] as Record<string, unknown>;
  expect(query).toMatchObject({ level: ["alto"], new: true, sort: "path", q: "sql" });
  expect(query.status).toBeUndefined(); // `status=any`: nessun filtro sullo stato
  expect(screen.getByRole("button", { name: "Rimuovi filtro tutti gli stati" })).toBeDefined();
});

test("frecce, j e k muovono il fuoco tra i titoli; / porta alla ricerca solo dalla tabella", async () => {
  const user = userEvent.setup();
  mount(fakeClient(page([item(1), item(2), item(3)])));
  const links = await screen.findAllByRole("link");
  at(links, 0).focus();
  await user.keyboard("j");
  expect(document.activeElement).toBe(links[1]);
  await user.keyboard("{ArrowDown}");
  expect(document.activeElement).toBe(links[2]);
  await user.keyboard("k");
  expect(document.activeElement).toBe(links[1]);
  await user.keyboard("{Home}");
  expect(document.activeElement).toBe(links[0]);
  await user.keyboard("{End}");
  expect(document.activeElement).toBe(links[2]);
  await user.keyboard("/");
  expect(document.activeElement).toBe(screen.getByRole("searchbox"));
  await user.keyboard("j"); // dentro il campo, `j` è una lettera
  expect(screen.getByRole<HTMLInputElement>("searchbox").value).toBe("j");
});

test("Invio su un titolo apre il dettaglio con i filtri nell'indirizzo", async () => {
  const user = userEvent.setup();
  mount(fakeClient(page([item(7)])), `/r/${REPO}?level=alto`);
  const link = await screen.findByRole("link");
  link.focus();
  await user.keyboard("{Enter}");
  expect(screen.getByTestId("where").textContent).toBe(`/r/${REPO}/f/${item(7).id}?level=alto`);
  await waitFor(() => {
    expect(document.querySelector("tr[aria-current='true']")?.textContent).toContain("Problema 7");
  });
});

test("Carica altri aggiunge la pagina successiva con il suo cursore e annuncia il risultato", async () => {
  const user = userEvent.setup();
  const listFindings = vi
    .fn()
    .mockResolvedValueOnce(page([item(1), item(2)], 3, "cur-1"))
    .mockResolvedValueOnce(page([item(3)], 3, null));
  mount(fakeClient(page([]), { listFindings }));
  await screen.findByText("2 di 3");
  await user.click(screen.getByRole("button", { name: "Carica altri" }));
  await screen.findByText("Problema 3");
  expect(listFindings.mock.calls[1]?.[1]).toMatchObject({ cursor: "cur-1" });
  expect(screen.getByText("3 di 3")).toBeDefined();
  expect(screen.queryByRole("button", { name: "Carica altri" })).toBeNull();
  expect(screen.getByRole("status").textContent).toContain("1 finding aggiunti");
});

test("una scansione parziale mette una fascia sopra la lista, con i plugin falliti e il collegamento", async () => {
  const scan = { ...example("ScanSummary"), status: "partial" as const };
  const client = fakeClient(page([item(1)]), {
    getRepository: vi.fn(() => Promise.resolve(repo({ current_scan: scan }))),
    getScan: vi.fn(() =>
      Promise.resolve({
        summary: scan,
        plugins: [{ name: "semgrep", outcome: "failed" }, { name: "ruff", outcome: "ok" }],
      }),
    ),
  } as unknown as Partial<Client>);
  mount(client);
  const banner = await screen.findByText(/Scansione parziale/);
  await waitFor(() => { expect(banner.parentElement?.textContent).toContain("1 plugin non riuscito (semgrep)"); });
  expect(banner.parentElement?.textContent).toContain("Nessun finding è stato segnato come risolto");
  expect(within(banner.parentElement as HTMLElement).getByRole("link", { name: "Vai alla scansione" }).getAttribute("href")).toBe(`/r/${REPO}/scans/${scan.id}`);
});

test("gli stati vuoti dicono cosa è successo e cosa fare", async () => {
  const user = userEvent.setup();
  // nessuna scansione
  const none = fakeClient(page([]), { getRepository: vi.fn(() => Promise.resolve(repo({ current_scan: null }))) });
  mount(none);
  expect(await screen.findByText(/Nessuna scansione ricevuta/)).toBeDefined();
  expect(screen.getByText("code-analyzer upload")).toBeDefined();
  cleanup();
  // nessun finding, scansione parziale
  const scan = { ...example("ScanSummary"), status: "partial" as const };
  mount(fakeClient(page([]), { getRepository: vi.fn(() => Promise.resolve(repo({ current_scan: scan }))), getScan: vi.fn(() => Promise.resolve({ summary: scan, plugins: [] })) } as unknown as Partial<Client>));
  expect(await screen.findByText("Nessun finding aperto.")).toBeDefined();
  expect(screen.getByText(/non è una buona notizia/)).toBeDefined();
  cleanup();
  // nessun finding con i filtri
  mount(fakeClient(page([])), `/r/${REPO}?level=critico`);
  expect(await screen.findByText(/Nessun finding con questi filtri/)).toBeDefined();
  await user.click(screen.getByRole("button", { name: "Azzera filtri" })); // un solo pulsante, quello della barra
  await waitFor(() => { expect(screen.getByTestId("where").textContent).toBe(`/r/${REPO}`); });
});

test("un errore del server è un avviso con il codice e Riprova rifà la richiesta", async () => {
  const user = userEvent.setup();
  const listFindings = vi
    .fn()
    .mockRejectedValueOnce(new ApiError(500, "internal-error", null))
    .mockResolvedValueOnce(page([item(1)]));
  mount(fakeClient(page([]), { listFindings }));
  const alert = await screen.findByRole("alert");
  expect(alert.textContent).toContain("internal-error");
  await user.click(within(alert).getByRole("button", { name: "Riprova" }));
  await screen.findByText("Problema 1");
  expect(listFindings).toHaveBeenCalledTimes(2);
});

test("un repository inesistente o negato non mostra la lista", async () => {
  mount(fakeClient(page([]), { getRepository: vi.fn(() => Promise.reject(new ApiError(404, "not-found", null))) }));
  expect((await screen.findByRole("alert")).textContent).toContain("non trovato");
  expect(screen.queryByRole("table")).toBeNull();
});

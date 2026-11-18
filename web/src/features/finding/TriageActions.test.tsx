import { cleanup, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Route, Routes } from "react-router";
import { afterEach, expect, test, vi } from "vitest";

import { ApiError } from "@/api/client";
import type { Client, Schemas } from "@/api/client";
import { example } from "@/api/examples";
import { FindingsPage } from "@/features/findings/FindingsPage";
import { renderInSession } from "@/test-utils";
import { FindingPanel } from "./FindingPanel";
import { exceptionSnippet } from "./TriageActions";

afterEach(cleanup);

const REPO = "0192f3a2-7c1e-7b55-9d0a-3f6c8e2b4a11";
const FID = "0192f3a2-7c1e-7b55-9d0a-000000000001";
const FP = "sha256:" + "a".repeat(64);

type Detail = Schemas["FindingDetail"];

function me(...roles: Schemas["Role"][]): Schemas["Me"] {
  return { ...example("Me"), name: "Ada", roles };
}

function detail(over: Partial<Schemas["Finding"]> = {}, rest: Partial<Detail> = {}): Detail {
  return {
    finding: {
      id: FID, fingerprint: FP, category: "sast", rule_id: "r", tool: "bandit", tools: ["bandit"], title: "Un problema", message: "m",
      location: { repository: "shop", path: "a.py", start_line: 1 }, first_seen: "2026-06-01T12:00:00Z", last_seen: "2026-11-17T12:00:00Z",
      status: "aperto", level: "alto", ...over,
    },
    occurrence: { scan_id: "s", commit: "c".repeat(40), variant_scores: [] },
    exceptions: [], events: [], ...rest,
  };
}

const reply = (value: Detail) => vi.fn<Client["patchFinding"]>(() => Promise.resolve(value));

function mount(current: Detail, user: Schemas["Me"], patch = reply(current), route = `/r/${REPO}/f/${FID}`) {
  const client = {
    getFinding: vi.fn(() => Promise.resolve(current)),
    patchFinding: patch,
    getRepository: vi.fn(() => Promise.resolve({ ...example("RepositorySummary"), current_scan: { ...example("ScanSummary"), status: "complete" } })),
    listFindings: vi.fn(() => Promise.resolve({ items: [{ ...example("FindingListItem"), id: FID, title: "Un problema", status: current.finding.status }], total: 1, total_new: 0, next_cursor: null })),
  } as unknown as Client;
  renderInSession(
    <Routes>
      <Route path="/r/:repository" element={<FindingsPage />}>
        <Route path="f/:finding" element={<FindingPanel />} />
      </Route>
    </Routes>,
    client,
    route,
    user,
  );
  return { patch };
}

const actions = async () => within(await screen.findByRole("region", { name: "Azioni" }));

test("un lettore non vede la sezione delle azioni", async () => {
  mount(detail(), me("lettore"));
  await screen.findByRole("complementary");
  expect(screen.queryByRole("region", { name: "Azioni" })).toBeNull();
});

test("chi ha solo il triage vede le azioni da approvatore disattivate, con il motivo, e raggiungibili", async () => {
  mount(detail(), me("lettore", "triage"));
  const section = await actions();
  const fp = section.getByRole("button", { name: "Segna come falso positivo" });
  expect(fp.getAttribute("aria-disabled")).toBe("true");
  expect(fp.getAttribute("aria-describedby")).toBeTruthy();
  expect(section.getAllByText("Serve il ruolo approvatore.").length).toBe(2);
  expect(section.getByRole("button", { name: "Prendi in carico" })).toBeDefined();
  fp.focus();
  expect(document.activeElement).toBe(fp); // raggiungibile da tastiera
  await userEvent.setup().click(fp);
  expect(screen.queryByRole("dialog")).toBeNull(); // e non apre nulla
});

test("Prendi in carico propone chi agisce, assegna, mette in corso e annuncia l'esito", async () => {
  const user = userEvent.setup();
  const after = detail({ status: "in_corso", owner: "Ada" });
  const { patch } = mount(detail(), me("lettore", "triage"), reply(after));
  await user.click((await actions()).getByRole("button", { name: "Prendi in carico" }));
  const dialog = await screen.findByRole("dialog", { name: "Prendi in carico" });
  const owner = within(dialog).getByLabelText(/Assegnato a/);
  expect((owner as HTMLInputElement).value).toBe("Ada");
  await user.click(within(dialog).getByRole("button", { name: "Prendi in carico" }));
  await waitFor(() => { expect(screen.queryByRole("dialog")).toBeNull(); });
  expect(patch.mock.calls.map((c) => c[1])).toEqual([
    { action: "set-owner", owner: "Ada" },
    { action: "set-status", status: "in_corso" },
  ]);
  expect(screen.getByRole("status").textContent).toContain("Stato aggiornato: In corso");
  // il pulsante non c'è più (ora è in corso): il fuoco va al titolo del pannello, non al corpo della pagina
  expect(document.activeElement?.id).toBe("panel-title");
});

test("la riga della lista segue il nuovo stato sul posto, anche se i filtri non la includerebbero più", async () => {
  const user = userEvent.setup();
  const after = detail({ status: "falso_positivo" });
  mount(detail(), me("lettore", "triage", "approvatore"), reply(after));
  await user.click((await actions()).getByRole("button", { name: "Segna come falso positivo" }));
  const dialog = await screen.findByRole("dialog");
  await user.type(within(dialog).getByLabelText(/Motivazione/), "validato a monte");
  await user.click(within(dialog).getByRole("button", { name: "Segna come falso positivo" }));
  await waitFor(() => { expect(screen.queryByRole("dialog")).toBeNull(); });
  const row = screen.getByRole("link", { name: /Un problema/ }).closest("tr");
  expect(row?.textContent).toContain("Falso positivo"); // la riga resta, con il nuovo stato
});

test("un campo obbligatorio vuoto non invia nulla, mostra l'errore accanto al campo e porta lì il fuoco", async () => {
  const user = userEvent.setup();
  const { patch } = mount(detail(), me("lettore", "triage", "approvatore"));
  await user.click((await actions()).getByRole("button", { name: "Segna come falso positivo" }));
  const dialog = await screen.findByRole("dialog");
  await user.click(within(dialog).getByRole("button", { name: "Segna come falso positivo" }));
  const field = within(dialog).getByLabelText(/Motivazione/);
  expect(patch).not.toHaveBeenCalled();
  expect(document.activeElement).toBe(field);
  expect(field.getAttribute("aria-invalid")).toBe("true");
  const error = document.getElementById(field.getAttribute("aria-describedby") ?? "");
  expect(error?.textContent).toBe("Scrivi la motivazione.");
  expect(within(dialog).getByText(/\(obbligatorio\)/)).toBeDefined(); // lo dice il testo, non un asterisco
});

test("l'eccezione chiede motivazione e una data futura scrivibile; mostra chi approva e il frammento per il gate", async () => {
  const user = userEvent.setup();
  const { patch } = mount(detail(), me("lettore", "triage", "approvatore"));
  await user.click((await actions()).getByRole("button", { name: "Accetta con eccezione" }));
  const dialog = await screen.findByRole("dialog", { name: "Accetta con eccezione" });
  const expires = within(dialog).getByLabelText(/Scadenza/);
  expect(within(dialog).getByText("Formato AAAA-MM-GG.")).toBeDefined();
  await user.type(within(dialog).getByLabelText(/Motivazione/), "migrazione");
  for (const bad of ["domani", "30/06/2027", "2020-01-01", "2027-13-45"]) {
    await user.clear(expires);
    await user.type(expires, bad);
    await user.click(within(dialog).getByRole("button", { name: "Accetta con eccezione" }));
    expect(patch).not.toHaveBeenCalled();
    expect(document.getElementById(expires.getAttribute("aria-describedby")?.split(" ").pop() ?? "")?.textContent).toBeTruthy();
  }
  await user.clear(expires);
  await user.type(expires, "2027-06-30");
  const snippet = within(dialog).getByLabelText("Frammento di .code-analyzer.yml");
  expect(snippet.textContent).toBe(exceptionSnippet(FP, "migrazione", "2027-06-30", "Ada"));
  expect(within(dialog).getByText(/Approva:/).textContent).toContain("Ada");
  // T8: l'avviso sul gate sta prima del pulsante di conferma nell'ordine di lettura
  const notice = within(dialog).getByText(/Il gate della CI non legge le eccezioni del server/);
  const confirm = within(dialog).getAllByRole("button", { name: "Accetta con eccezione" }).at(-1);
  expect(notice.compareDocumentPosition(confirm as Node) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  await user.click(confirm as HTMLElement);
  await waitFor(() => { expect(patch).toHaveBeenCalledWith(FID, { action: "create-exception", reason: "migrazione", expires: "2027-06-30" }); });
});

test("Copia mette il frammento negli appunti e lo annuncia", async () => {
  const user = userEvent.setup();
  const writeText = vi.spyOn(navigator.clipboard, "writeText").mockResolvedValue(undefined);
  mount(detail(), me("lettore", "triage", "approvatore"));
  await user.click((await actions()).getByRole("button", { name: "Accetta con eccezione" }));
  const dialog = await screen.findByRole("dialog");
  await user.click(within(dialog).getByRole("button", { name: "Copia" }));
  expect(writeText).toHaveBeenCalledWith(expect.stringContaining(`fingerprint: ${FP}`));
  expect(within(dialog).getByRole("status").textContent).toContain("Copiato negli appunti");
});

test("l'eccezione del frammento non rompe il YAML con una motivazione ostile", () => {
  const text = exceptionSnippet(FP, 'chiude"\nexceptions: []', "2027-06-30", 'A"da');
  expect(text.split("\n")).toHaveLength(5); // la motivazione resta su una riga, tra virgolette
  expect(text).toContain('reason: "chiude\\"\\nexceptions: []"');
});

test("un errore del server lascia il dialogo aperto con i dati e mostra titolo e codice", async () => {
  const user = userEvent.setup();
  const failing = vi.fn<Client["patchFinding"]>(() => Promise.reject(new ApiError(403, "forbidden", { ...example("Problem"), title: "Ruolo mancante", code: "forbidden", status: 403 })));
  mount(detail(), me("lettore", "triage", "approvatore"), failing);
  await user.click((await actions()).getByRole("button", { name: "Segna come falso positivo" }));
  const dialog = await screen.findByRole("dialog");
  await user.type(within(dialog).getByLabelText(/Motivazione/), "testo che non si perde");
  await user.click(within(dialog).getByRole("button", { name: "Segna come falso positivo" }));
  const alert = await within(dialog).findByRole("alert");
  expect(alert.textContent).toContain("Ruolo mancante");
  expect(alert.textContent).toContain("forbidden");
  expect(within(dialog).getByLabelText<HTMLTextAreaElement>(/Motivazione/).value).toBe("testo che non si perde");
  expect(screen.queryByRole("dialog")).not.toBeNull();
});

test("Esc senza testo chiude; con testo chiede conferma prima di scartare", async () => {
  const user = userEvent.setup();
  mount(detail(), me("lettore", "triage", "approvatore"));
  await user.click((await actions()).getByRole("button", { name: "Segna come falso positivo" }));
  await screen.findByRole("dialog");
  await user.keyboard("{Escape}");
  await waitFor(() => { expect(screen.queryByRole("dialog")).toBeNull(); });
  expect(screen.queryByRole("complementary")).not.toBeNull(); // Esc del dialogo non chiude anche il pannello
  await user.click((await actions()).getByRole("button", { name: "Segna come falso positivo" }));
  const dialog = await screen.findByRole("dialog");
  await user.type(within(dialog).getByLabelText(/Motivazione/), "scritto");
  await user.keyboard("{Escape}");
  expect((await within(dialog).findByRole("alert")).textContent).toContain("Chiudere comunque?");
  await user.click(within(dialog).getByRole("button", { name: "Continua a modificare" }));
  expect(screen.queryByRole("dialog")).not.toBeNull();
  await user.keyboard("{Escape}");
  await user.click(await within(dialog).findByRole("button", { name: "Scarta" }));
  await waitFor(() => { expect(screen.queryByRole("dialog")).toBeNull(); });
});

test("Revoca l'eccezione è un'azione da approvatore e invia l'identificativo dell'eccezione", async () => {
  const user = userEvent.setup();
  const accepted = detail({ status: "accettato" }, { exceptions: [{ id: "ex-1", origin: "server", reason: "r", expires: "2999-01-01", approved_by: "x", approved_by_verified: true }] });
  const { patch } = mount(accepted, me("lettore", "triage", "approvatore"), reply(detail()));
  await user.click((await actions()).getByRole("button", { name: "Revoca l'eccezione" }));
  await waitFor(() => { expect(patch).toHaveBeenCalledWith(FID, { action: "revoke-exception", exception_id: "ex-1" }); });
  cleanup();
  mount(accepted, me("lettore", "triage"));
  const disabled = (await actions()).getByRole("button", { name: "Revoca l'eccezione" });
  expect(disabled.getAttribute("aria-disabled")).toBe("true");
});

test("un'eccezione del repository non si revoca da qui e lo dice", async () => {
  const accepted = detail({ status: "accettato" }, { exceptions: [{ id: "ex-2", origin: "repository", reason: "r", expires: "2999-01-01", approved_by: "x", approved_by_verified: false }] });
  mount(accepted, me("lettore", "triage", "approvatore"));
  const section = await actions();
  expect(section.queryByRole("button", { name: /Revoca/ })).toBeNull();
  expect(section.getByText(/dichiarata nel repository/)).toBeDefined();
});

test("un finding risolto non ha azioni", async () => {
  mount(detail({ status: "risolto" }), me("lettore", "triage", "approvatore"));
  const section = await actions();
  expect(section.queryByRole("button")).toBeNull();
  expect(section.getByText(/lo assegna il server/)).toBeDefined();
});

test("Riapri toglie un finding in corso dallo stato in corso con una sola richiesta", async () => {
  const user = userEvent.setup();
  const { patch } = mount(detail({ status: "in_corso" }), me("lettore", "triage"), reply(detail()));
  await user.click((await actions()).getByRole("button", { name: "Riapri" }));
  await waitFor(() => { expect(patch).toHaveBeenCalledWith(FID, { action: "set-status", status: "aperto" }); });
  expect(patch).toHaveBeenCalledTimes(1);
});

test("G11: il testo scritto in un dialogo sopravvive a un ricaricamento della pagina e si cancella a invio riuscito", async () => {
  const user = userEvent.setup();
  mount(detail(), me("lettore", "triage", "approvatore"));
  await user.click((await actions()).getByRole("button", { name: "Segna come falso positivo" }));
  await user.type(within(await screen.findByRole("dialog")).getByLabelText(/Motivazione/), "scritto prima della scadenza");
  cleanup(); // la pagina si ricarica dopo il giro dall'IdP: i componenti nascono da capo
  mount(detail(), me("lettore", "triage", "approvatore"));
  await user.click((await actions()).getByRole("button", { name: "Segna come falso positivo" }));
  const field = within(await screen.findByRole("dialog")).getByLabelText<HTMLTextAreaElement>(/Motivazione/);
  expect(field.value).toBe("scritto prima della scadenza");
  await user.click(screen.getByRole("button", { name: "Segna come falso positivo", description: "" }).closest("form")?.querySelector("button[type='submit']") as HTMLElement);
  await waitFor(() => { expect(screen.queryByRole("dialog")).toBeNull(); });
  expect(Object.keys(window.sessionStorage).filter((k) => k.startsWith("ca.draft."))).toEqual([]);
});

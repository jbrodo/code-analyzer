"use strict";
// Tutto ciò che viene dal campione e dal codice entra nella pagina solo come testo.
const token = new URLSearchParams(location.hash.slice(1)).get("t") ?? "";
const BUCKETS = [
  [1, "Subito"],
  [2, "Presto"],
  [3, "Quando capita"],
  [4, "Mai, o non è un problema"],
];
const CATEGORY = { quality: "Qualità", architecture: "Architettura", sast: "Sicurezza del codice",
  dependency: "Dipendenza", iac: "Infrastruttura", secret: "Segreto", license: "Licenza",
  test: "Test", health: "Salute" };
const READING_MS = 300; // dopo un cambio di finding: una doppia pressione non vota quello nuovo
const $ = (id) => document.getElementById(id);
const el = (tag, text, attributes = {}) => {
  const node = document.createElement(tag);
  if (text !== undefined && text !== null) node.textContent = text;
  for (const [name, value] of Object.entries(attributes)) node.setAttribute(name, value);
  return node;
};
const memory = {
  get(key) { try { return localStorage.getItem("gate2." + key); } catch { return null; } },
  set(key, value) { try { localStorage.setItem("gate2." + key, value); } catch { /* facoltativo */ } },
};

let repos = [], repo = null, items = [], state = null, delivery = null, revision = 0;
let current = 0, view = "classify", codeView = "normal", selected = null, listScroll = 0;
let dirty = false, inflight = null, failure = null, noteTimer = null, history = [], lastVote = "";
let codeReady = false, codeFailed = false, readable = false, readableTimer = null;
const requests = { code: 0, detail: 0 };

async function api(path, method = "GET", body) {
  let response, data;
  try {
    response = await fetch("api/" + path, {
      method, headers: { "X-Token": token }, body: body === undefined ? undefined : JSON.stringify(body),
    });
    data = await response.json();
  } catch {
    throw Object.assign(new Error("Il server non risponde. Controlla che review.py sia in esecuzione."), { status: 0 });
  }
  if (!response.ok) throw Object.assign(new Error(data.error ?? "Richiesta non riuscita."), { status: response.status });
  return data;
}

// --- avvisi e salvataggio -------------------------------------------------------------------------

function notice(text, action, label) {
  $("alert").hidden = !text;
  $("alert-text").textContent = text ?? "";
  $("alert-action").hidden = !action;
  $("alert-action").textContent = label ?? "";
  $("alert-action").onclick = action ?? null;
}

function fail(error) {
  notice(error.message);
}

function renderSave() {
  const text = failure ? "Non salvato" : inflight || dirty ? "Salvo…" : "Salvato";
  if ($("saved").textContent !== text) $("saved").textContent = text;
  $("saved").classList.toggle("bad", failure !== null);
}

// Un salvataggio alla volta, sempre dall'ultima revisione. Se fallisce ci si ferma: niente voti,
// niente consegna, finché non riesce.
function pump() {
  clearTimeout(noteTimer);
  if (inflight || failure || !dirty) return inflight ?? Promise.resolve();
  const name = repo;
  inflight = (async () => {
    while (dirty && !failure) {
      dirty = false;
      try {
        ({ revision } = await api("state/" + name, "PUT", { ...structuredClone(state), revision }));
      } catch (error) {
        dirty = true;
        failure = error;
      }
    }
  })().finally(() => {
    inflight = null;
    renderSave();
    if (failure) {
      if (failure.status === 409) {
        notice(`Non salvato: ${failure.message}. Le modifiche di questa pagina dopo l'ultimo «Salvato» vanno rifatte.`, () => { dirty = false; failure = null; location.reload(); }, "Ricarica la pagina");
      } else {
        notice(`Non salvato. ${failure.message} Voti e consegna sono fermi finché non riesco a salvare.`, () => { failure = null; notice(null); pump(); renderAll(); }, "Riprova");
      }
      renderAll();
    }
  });
  renderSave();
  return inflight;
}

function changed() {
  dirty = true;
  pump();
}

async function flush() {
  await pump();
  return !dirty && !failure;
}

const frozen = () => delivery !== null || failure !== null;

// --- stato ----------------------------------------------------------------------------------------

const item = () => items[current];
const byNumber = (n) => items.find((i) => i.n === n);
const bucketOf = (n) => state.buckets[n] ?? null;
const assigned = () => Object.keys(state.buckets).length;
const label = (bucket) => BUCKETS[bucket - 1][1];
const members = (bucket) => items.map((i) => i.n).filter((n) => bucketOf(n) === bucket).sort((a, b) => a - b);

function remember(description, n) {
  history.push({ description, n, buckets: { ...state.buckets }, tiers: { ...state.tiers } });
  if (history.length > 100) history.shift();
}

function undo() {
  if (frozen() || history.length === 0) return;
  const step = history.pop();
  state.buckets = step.buckets;
  state.tiers = step.tiers;
  changed();
  lastVote = `Annullato: ${step.description}`;
  $("status").textContent = lastVote;
  if (view === "classify") show(items.indexOf(byNumber(step.n)));
  else { selected = step.n; renderArrange(); renderDetail(); renderTabs(); }
}

const canVote = () => !frozen() && codeReady && readable;

function assign(bucket) {
  if (!canVote()) return;
  const n = item().n, before = bucketOf(n);
  if (before === bucket) {
    $("status").textContent = `Il finding ${n} è già in «${label(bucket)}».`;
    return;
  }
  const description = `finding ${n} in «${label(bucket)}»`;
  remember(description, n);
  state.buckets[n] = bucket;
  delete state.tiers[n];
  changed();
  lastVote = `Finding ${n}: ${label(bucket)}`;
  $("status").textContent = lastVote;
  const after = items.findIndex((i, index) => index > current && bucketOf(i.n) === null);
  const target = after >= 0 ? after : items.findIndex((i) => bucketOf(i.n) === null);
  // correggendo un voto già dato si resta dove si è
  if (before === null && target >= 0) show(target);
  else { renderCard(); renderTabs(); }
  if (before === null && target < 0) $("status").textContent = `${lastVote}. Tutti classificati: puoi riordinare e consegnare.`;
  $("title").focus({ preventScroll: true });
}

// --- classifica -----------------------------------------------------------------------------------

function renderTabs() {
  if ($("repos").children.length !== repos.length) {
    $("repos").replaceChildren(...repos.map((r) => {
      const button = el("button", null, { type: "button", "data-repo": r.name });
      button.addEventListener("click", () => open(r.name));
      return button;
    }));
  }
  repos.forEach((r, index) => { // si aggiorna il testo: ricreare i pulsanti perderebbe il fuoco
    const button = $("repos").children[index];
    const mine = r.name === repo;
    const delivered = mine ? delivery !== null : r.delivered;
    button.textContent = `${r.name} · ${delivered ? "consegnato" : `${mine ? assigned() : r.assigned} di ${r.total}`}`;
    button.setAttribute("aria-current", String(mine));
  });
  for (const button of $("steps").children) button.setAttribute("aria-current", String(button.dataset.view === view));
  document.title = `${repo} · ${view === "classify" ? "Classifica" : "Riordina e consegna"} · Valutazione`;
}

function renderVoting() {
  // i 300 ms di lettura non si disegnano: lampeggerebbero a ogni voto
  const blocked = frozen() || codeFailed;
  for (const button of $("buckets").querySelectorAll("button")) {
    button.setAttribute("aria-pressed", String(bucketOf(item().n) === Number(button.dataset.bucket)));
    button.setAttribute("aria-disabled", String(blocked));
  }
}

function renderCard() {
  const it = item();
  const complete = assigned() === items.length;
  $("position").textContent = `Finding ${current + 1} di ${items.length}`;
  $("done").textContent = delivery ? "ordinamento consegnato" : `${assigned()} classificati`;
  $("title").textContent = it.title;
  $("category").textContent = CATEGORY[it.category] ?? it.category;
  $("rule").textContent = it.rule;
  $("message").textContent = it.message === it.title ? "" : it.message;
  $("where").textContent = it.position;
  if (document.activeElement !== $("note")) $("note").value = state.notes[it.n] ?? "";
  $("note").readOnly = frozen();
  $("last").textContent = complete && !delivery ? `${lastVote ? lastVote + ". " : ""}Tutti classificati.` : lastVote;
  $("undo").setAttribute("aria-disabled", String(frozen() || history.length === 0));
  $("previous").setAttribute("aria-disabled", String(current === 0));
  $("next").setAttribute("aria-disabled", String(current === items.length - 1));
  $("unassigned").textContent = complete ? "Vai a riordinare →" : "Primo da classificare";
  $("unassigned").classList.toggle("primary", complete && !delivery);
  renderVoting();
}

function codeBlocks(found) {
  return found.blocks.map((block) => {
    const list = el("ol", null, { class: "block", "aria-label": `Righe da ${block.start} a ${block.start + block.lines.length - 1}` });
    block.lines.forEach((text, index) => {
      const number = block.start + index;
      const row = el("li");
      row.append(el("span", String(number), { class: "number" }));
      if (number === block.highlight) {
        row.setAttribute("class", "marked");
        row.append(el("span", "riga indicata: ", { class: "visually-hidden" }));
      }
      row.append(el("code", text || " "));
      list.append(row);
    });
    return list;
  });
}

// La riga indicata a un terzo del riquadro, così si legge anche ciò che segue. Scorre solo il
// riquadro, mai la pagina.
function centre(container) {
  const marked = container.querySelector(".marked");
  container.scrollTop = 0;
  container.scrollLeft = 0;
  if (!marked) return;
  const offset = marked.getBoundingClientRect().top - container.getBoundingClientRect().top;
  container.scrollTop = offset - container.clientHeight / 3;
}

async function renderCode() {
  const request = ++requests.code;
  codeReady = false;
  codeFailed = false;
  renderVoting();
  $("code").replaceChildren();
  $("code-note").textContent = "Carico il codice…";
  $("code-retry").hidden = true;
  $("wide").textContent = codeView === "wide" ? "Meno contesto" : "Più contesto";
  $("full").textContent = codeView === "full" ? "Solo il punto" : "File intero";
  try {
    const found = await api(`evidence/${repo}/${item().n}?view=${codeView}`);
    if (request !== requests.code) return; // intanto si è passati a un altro finding
    $("code-note").textContent = found.note;
    $("code").replaceChildren(...codeBlocks(found));
    centre($("code"));
    codeReady = true;
  } catch (error) {
    if (request !== requests.code) return;
    $("code-note").textContent = `Codice non caricato. ${error.message} Senza codice non si vota.`;
    $("code-retry").hidden = false;
    codeFailed = true;
  }
  renderVoting();
}

function show(index) {
  const next = Math.max(0, Math.min(items.length - 1, index));
  const moved = next !== current;
  current = next;
  codeView = "normal";
  readable = false;
  clearTimeout(readableTimer);
  readableTimer = setTimeout(() => { readable = true; }, READING_MS);
  renderCard();
  renderTabs();
  renderCode();
  if (moved) {
    document.querySelector(".card-text").scrollTop = 0;
    if (window.scrollY > 0) $("card").scrollIntoView({ block: "start" });
  }
}

// --- riordina -------------------------------------------------------------------------------------

function applyMove(n, action) {
  if (frozen()) return;
  const bucket = bucketOf(n);
  const group = members(bucket);
  if (!Bands.canMove(group, state.tiers, n, action)) return;
  const names = { top: "in cima", up: "un gradino su", down: "un gradino giù", bottom: "in fondo", reset: "tra i non spostati" };
  const description = `finding ${n} ${names[action]} in «${label(bucket)}»`;
  remember(description, n);
  state.tiers = Bands.move(group, state.tiers, n, action);
  changed();
  renderArrange();
  renderTools();
  const bands = Bands.bandsOf(group, state.tiers);
  const at = bands.findIndex((band) => band.ids.includes(n));
  $("status").textContent = `Finding ${n}: fascia ${at + 1} di ${bands.length} in «${label(bucket)}», ${bands[at].ids.length > 1 ? `alla pari con altri ${bands[at].ids.length - 1}` : "da solo"}.`;
  document.querySelector(`[data-row="${n}"]`)?.scrollIntoView({ block: "nearest" });
}

function renderTools() {
  const group = selected === null || bucketOf(selected) === null ? [] : members(bucketOf(selected));
  for (const button of $("detail-tools").children) {
    const possible = !frozen() && group.length > 0 && Bands.canMove(group, state.tiers, selected, button.dataset.action);
    button.setAttribute("aria-disabled", String(!possible));
  }
  for (const row of document.querySelectorAll("[data-row]")) row.setAttribute("aria-current", String(Number(row.dataset.row) === selected));
}

async function renderDetail() {
  const request = ++requests.detail;
  const it = selected === null ? null : byNumber(selected);
  $("detail-title").textContent = it ? `${it.n}. ${it.title}` : "Nessun finding scelto";
  $("detail-empty").hidden = it !== null;
  $("detail-body").hidden = it === null;
  $("detail-category").textContent = it ? (CATEGORY[it.category] ?? it.category) : "";
  $("detail-rule").textContent = it?.rule ?? "";
  $("detail-where").textContent = it?.position ?? "";
  $("detail-message").textContent = it && it.message !== it.title ? it.message : "";
  $("detail-note").textContent = it && state.notes[it.n] ? `La tua nota: ${state.notes[it.n]}` : "";
  $("detail-code").replaceChildren();
  renderTools();
  if (!it) return;
  try {
    const found = await api(`evidence/${repo}/${it.n}`);
    if (request !== requests.detail) return;
    $("detail-code").replaceChildren(el("p", found.note, { class: "muted" }), ...codeBlocks(found));
    centre($("detail-code"));
  } catch (error) {
    if (request === requests.detail) $("detail-code").replaceChildren(el("p", `Codice non caricato. ${error.message}`));
  }
}

function select(n) {
  selected = n;
  renderDetail();
  if (matchMedia("(max-width: 60rem)").matches) { // il dettaglio sta sopra l'elenco
    $("detail").scrollIntoView({ block: "start" });
    $("detail-title").focus({ preventScroll: true });
  }
}

function rowFor(n) {
  const it = byNumber(n);
  const row = el("button", null, { type: "button", class: "row", "data-row": String(n), "aria-current": String(n === selected) });
  row.append(el("span", `${n}.`, { class: "num" }), el("strong", it.title), el("code", `${it.rule} · ${it.position}`));
  if (state.notes[n]) row.append(el("span", state.notes[n], { class: "muted" }));
  row.addEventListener("click", () => select(n));
  row.addEventListener("keydown", (event) => {
    if (!event.altKey || !["ArrowUp", "ArrowDown"].includes(event.key)) return;
    event.preventDefault();
    if (event.repeat) return;
    const moveRow = selected !== n;
    selected = n;
    applyMove(n, event.key === "ArrowUp" ? "up" : "down");
    if (moveRow) renderDetail();
    document.querySelector(`[data-row="${n}"]`)?.focus();
  });
  const li = el("li");
  li.append(row);
  return li;
}

function renderArrange() {
  const focused = document.activeElement?.dataset?.row;
  const keep = $("groups").scrollTop;
  let position = 1;
  $("groups").replaceChildren(...BUCKETS.map(([bucket, name]) => {
    const group = members(bucket);
    const section = el("section", null, { class: "group" });
    const head = el("div", null, { class: "group-head" });
    head.append(el("h2", `${name} (${group.length})`));
    const moved = group.some((n) => state.tiers[n]);
    if (moved && !frozen()) {
      const reset = el("button", "Rimetti tutti alla pari", { type: "button" });
      reset.addEventListener("click", () => {
        const description = `ordine di «${name}»`;
        remember(description, group[0]);
        for (const n of group) delete state.tiers[n];
        changed();
        renderArrange();
        renderTools();
        $("status").textContent = `«${name}»: tutti alla pari. Si può annullare.`;
        $("arrange-undo").focus();
      });
      head.append(reset);
    }
    section.append(head);
    if (group.length === 0) section.append(el("p", "Nessun finding in questo gruppo.", { class: "muted" }));
    for (const band of Bands.bandsOf(group, state.tiers)) {
      if (band.ids.length === 0) continue;
      const size = band.ids.length;
      const kind = size > 1 ? `${size} alla pari` : "da solo";
      const untouched = moved && band.tier === 0 ? " · non spostati" : "";
      const list = el("ul", null, { class: "band" });
      list.append(...band.ids.map(rowFor));
      section.append(el("h3", `Posizione ${position} · ${kind}${untouched}`), list);
      position += size;
    }
    return section;
  }));
  $("groups").scrollTop = keep;
  if (focused) document.querySelector(`[data-row="${focused}"]`)?.focus({ preventScroll: true });
  const missing = items.length - assigned();
  $("deliver-state").textContent = delivery
    ? `Consegnato il ${new Date(delivery.delivered_at).toLocaleString("it")}. Impronta ${delivery.sha256.slice(0, 16)}… Prima del prossimo repository, se sei stanco, fai una pausa.`
    : missing ? `Mancano ${missing} finding da classificare.` : "Tutti i finding sono classificati.";
  $("deliver").hidden = delivery !== null;
  $("deliver").setAttribute("aria-disabled", String(missing > 0 || failure !== null));
  $("arrange-undo").hidden = delivery !== null;
  $("arrange-undo").setAttribute("aria-disabled", String(frozen() || history.length === 0));
  const other = repos.find((r) => r.name !== repo && !r.delivered);
  $("next-repo").hidden = delivery === null || !other;
  if (other) {
    $("next-repo").textContent = `Passa a ${other.name}`;
    $("next-repo").onclick = async () => { await open(other.name); setView("classify"); $("title").focus(); };
  }
}

// --- consegna -------------------------------------------------------------------------------------

let shownSummary = null;
const canonical = (value) => JSON.stringify(value, (key, v) =>
  v && typeof v === "object" && !Array.isArray(v) ? Object.fromEntries(Object.entries(v).sort(([a], [b]) => a.localeCompare(b))) : v);

async function reviewDelivery() {
  if (frozen() || assigned() < items.length) return;
  try {
    if (!(await flush())) return;
    const found = await api("preview/" + repo);
    const mine = { buckets: state.buckets, tiers: state.tiers, notes: state.notes };
    if (found.revision !== revision || canonical(found.state) !== canonical(mine)) {
      notice("Ciò che è salvato non coincide con questa pagina (un'altra scheda?).", () => location.reload(), "Ricarica la pagina");
      return;
    }
    shownSummary = found;
    $("summary-title").textContent = `Stai per consegnare ${repo}`;
    const positions = new Set(found.rows.map((r) => r.rank)).size;
    $("summary-counts").textContent = BUCKETS.map(([b, name]) => `${name}: ${members(b).length}`).join(" · ") + ` · posizioni distinte: ${positions} su ${items.length} finding`;
    $("summary-rows").replaceChildren(...found.rows.map(({ n, rank }) => {
      const row = el("tr");
      row.append(el("td", String(rank)), el("td", String(n)), el("td", byNumber(n).title), el("td", label(bucketOf(n))));
      return row;
    }));
    $("confirm-yes").textContent = `Sì, consegna ${repo}`;
    $("arrange").hidden = true;
    $("summary").hidden = false;
    $("summary-title").focus();
  } catch (error) {
    fail(error);
  }
}

function closeSummary() {
  shownSummary = null;
  $("summary").hidden = true;
  $("arrange").hidden = view !== "arrange";
}

async function confirmDelivery() {
  if (!shownSummary || frozen()) return;
  const { revision: seen, sha256 } = shownSummary;
  shownSummary = null; // una sola richiesta
  try {
    delivery = await api("deliver/" + repo, "POST", { revision: seen, sha256 });
    repos = await api("repos");
    notice(null);
    closeSummary();
    renderArrange();
    renderTools();
    renderCard();
    renderTabs();
    $("status").textContent = `Ordinamento di ${repo} consegnato.`;
    $("deliver-state").setAttribute("tabindex", "-1");
    $("deliver-state").focus();
  } catch (error) {
    closeSummary();
    if (error.status === 409) notice(`Non consegnato: ${error.message}.`, () => location.reload(), "Ricarica la pagina");
    else fail(error);
  }
}

// --- viste ----------------------------------------------------------------------------------------

function renderAll() {
  if (!state) return;
  renderCard();
  renderTabs();
  if (view === "arrange") { renderArrange(); renderTools(); }
}

function setView(name) {
  if (view === "arrange" && !$("arrange").hidden) listScroll = $("groups").scrollTop;
  view = name;
  memory.set("view", name);
  $("summary").hidden = true;
  shownSummary = null;
  $("classify").hidden = name !== "classify";
  $("arrange").hidden = name !== "arrange";
  renderTabs();
  if (name === "arrange") {
    if (selected !== null && bucketOf(selected) === null) selected = null;
    renderArrange();
    $("groups").scrollTop = listScroll;
    renderDetail();
  }
}

async function open(name) {
  try {
    if (repo && !(await flush())) return; // non si lascia un repository con modifiche non salvate
    const [list, data] = await Promise.all([api("repos"), api("repo/" + name)]);
    repos = list; repo = name; items = data.items; state = data.state;
    revision = data.revision; delivery = data.delivery;
    history = []; lastVote = ""; selected = null; listScroll = 0; dirty = false;
    memory.set("repo", name);
    notice(null);
    renderSave();
    const first = items.findIndex((i) => bucketOf(i.n) === null);
    current = first >= 0 ? first : 0;
    setView(view);
    show(current);
  } catch (error) {
    fail(error);
  }
}

for (const [bucket, name] of BUCKETS) {
  const button = el("button", null, { type: "button", "data-bucket": String(bucket) });
  button.append(el("kbd", String(bucket)), document.createTextNode(" " + name));
  button.addEventListener("click", () => assign(bucket));
  $("buckets").append(button);
}
$("previous").addEventListener("click", () => { if (current > 0) show(current - 1); });
$("next").addEventListener("click", () => { if (current < items.length - 1) show(current + 1); });
$("unassigned").addEventListener("click", () => {
  const first = items.findIndex((i) => bucketOf(i.n) === null);
  if (first >= 0) show(first); else setView("arrange");
});
$("undo").addEventListener("click", undo);
$("arrange-undo").addEventListener("click", undo);
$("wide").addEventListener("click", () => { codeView = codeView === "wide" ? "normal" : "wide"; renderCode(); });
$("full").addEventListener("click", () => { codeView = codeView === "full" ? "normal" : "full"; renderCode(); });
$("code-retry").addEventListener("click", renderCode);
$("note").addEventListener("input", () => { // si salva mentre si scrive, non solo uscendo
  if (frozen()) return;
  const text = $("note").value;
  if (text.trim()) state.notes[item().n] = text; else delete state.notes[item().n];
  dirty = true;
  renderSave();
  clearTimeout(noteTimer);
  noteTimer = setTimeout(pump, 400);
});
$("note").addEventListener("blur", () => pump());
$("shortcuts").checked = memory.get("shortcuts") !== "off";
$("shortcuts").addEventListener("change", () => memory.set("shortcuts", $("shortcuts").checked ? "on" : "off"));
for (const button of $("steps").children) button.addEventListener("click", () => setView(button.dataset.view));
for (const button of $("detail-tools").children) button.addEventListener("click", () => applyMove(selected, button.dataset.action));
$("detail-open").addEventListener("click", () => { const n = selected; setView("classify"); show(items.indexOf(byNumber(n))); $("title").focus(); });
$("deliver").addEventListener("click", reviewDelivery);
$("confirm-no").addEventListener("click", () => { closeSummary(); $("deliver").focus(); });
$("confirm-yes").addEventListener("click", confirmDelivery);
window.addEventListener("beforeunload", (event) => { if (dirty || inflight || failure) event.preventDefault(); });

document.addEventListener("keydown", (event) => {
  // un tasto tenuto premuto non ripete mai un'azione sui pulsanti
  if (event.repeat && ["Enter", " "].includes(event.key) && event.target.closest("button")) { event.preventDefault(); return; }
  if (event.key === "Escape" && !$("summary").hidden) { closeSummary(); $("deliver").focus(); return; }
  if (view !== "classify" || !$("shortcuts").checked || event.ctrlKey || event.metaKey || event.altKey || event.shiftKey) return;
  // solo dentro «Classifica» (o senza fuoco), mai dall'intestazione né scrivendo
  if (event.target !== document.body && !event.target.closest("#classify")) return;
  if (event.target.closest("textarea, input")) return;
  const arrow = event.key === "ArrowRight" ? "next" : event.key === "ArrowLeft" ? "previous" : null;
  if (arrow && event.target.closest("#code")) return; // lì le frecce scorrono il codice
  const digit = ["1", "2", "3", "4"].includes(event.key);
  if (!digit && !arrow && event.key.toLowerCase() !== "z") return;
  event.preventDefault();
  if (event.repeat) return;
  if (digit) assign(Number(event.key));
  else if (arrow) $(arrow).click();
  else undo();
});

(async () => {
  try {
    repos = await api("repos");
    view = memory.get("view") === "arrange" ? "arrange" : "classify";
    const saved = memory.get("repo");
    await open(repos.some((r) => r.name === saved) ? saved : repos[0].name);
  } catch (error) {
    fail(error);
  }
})();

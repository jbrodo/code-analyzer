// Annotazione del golden set. Tutto ciò che viene dai repository annotati entra nella pagina
// solo come testo (`textContent`), mai come HTML.
"use strict";

const NAMES = { vero: "vero", "falso-positivo": "falso positivo", "non-so": "non so" };
const IDLE_MS = 120000; // senza attività per due minuti il tempo non si conta
const $ = (id) => document.getElementById(id);
const token = new URLSearchParams(location.hash.slice(1)).get("t") ?? "";

let items = [];
let state = null;
let delivered = null;
let current = 0;
let view = "normal";
let readable = false; // si risponde solo con il codice della voce sullo schermo
let broken = false; // un salvataggio fallito ferma tutto
let queue = Promise.resolve();
let pendingSaves = 0;
let undoStep = null;
let spent = 0;
let tick = Date.now();
let lastActivity = Date.now();

async function api(path, options = {}) {
  const response = await fetch(`/api/${path}`, {
    ...options,
    headers: { "X-Token": token, "Content-Type": "application/json" },
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error ?? `errore ${response.status}`);
  return data;
}

function stop(message) {
  broken = true;
  $("alert-text").textContent = message;
  $("alert").hidden = false;
  render();
}

// --- tempo -------------------------------------------------------------------------------------

function count() {
  const now = Date.now();
  if (document.visibilityState === "visible" && now - lastActivity < IDLE_MS) spent += now - tick;
  tick = now;
}
for (const event of ["keydown", "pointerdown", "pointermove", "wheel"]) {
  addEventListener(event, () => { count(); lastActivity = Date.now(); }, { passive: true, capture: true });
}
document.addEventListener("visibilitychange", count);
setInterval(count, 5000);

function takeSeconds() {
  count();
  const seconds = Math.min(Math.floor(spent / 1000), 3600);
  spent -= seconds * 1000;
  return seconds;
}

// --- salvataggio -------------------------------------------------------------------------------

function save(n) {
  if (broken || delivered) return queue;
  const key = String(n);
  const body = { label: state.labels[key] ?? null, note: state.notes[key] ?? "", seconds: takeSeconds() };
  pendingSaves += 1;
  $("saved").textContent = "Salvataggio…";
  queue = queue.then(async () => {
    if (broken) return;
    try {
      const done = await api(`item/${n}`, { method: "PUT", body: JSON.stringify({ ...body, revision: state.revision }) });
      state.revision = done.revision;
      pendingSaves -= 1;
      if (pendingSaves === 0) $("saved").textContent = "Salvato";
    } catch (error) {
      $("saved").textContent = "Non salvato";
      stop(`Non salvato: ${error.message}. L'ultima modifica va rifatta.`);
    }
  });
  return queue;
}

addEventListener("beforeunload", (event) => { if (pendingSaves > 0) event.preventDefault(); });

// --- pagina ------------------------------------------------------------------------------------

const answered = () => Object.keys(state.labels).length;
const locked = () => broken || delivered !== null;

function render() {
  if (!state) return;
  const item = items[current];
  const label = state.labels[String(item.n)] ?? null;
  const missing = items.length - answered();
  $("progress").textContent = `${answered()} di ${items.length} con risposta`;
  for (const button of document.querySelectorAll("#answers button")) {
    button.setAttribute("aria-pressed", String(button.dataset.label === label));
    button.setAttribute("aria-disabled", String(locked() || !readable));
  }
  $("note").readOnly = locked();
  $("previous").setAttribute("aria-disabled", String(current === 0));
  $("next").setAttribute("aria-disabled", String(current === items.length - 1));
  $("unanswered").hidden = missing === 0;
  $("undo").hidden = undoStep === null || locked();
  $("delivery-text").textContent = delivered
    ? `Consegnato in golden-set/${delivered}.`
    : missing ? `Per consegnare mancano ${missing} risposte.` : "Tutte le voci hanno una risposta. Dopo la consegna non si modificano.";
  $("deliver").hidden = missing > 0 || locked() || !$("confirm").hidden;
}

async function loadCode() {
  const item = items[current];
  readable = false;
  $("code").replaceChildren();
  $("code-note").textContent = "Carico il codice…";
  $("code-retry").hidden = true;
  for (const id of ["wide", "full"]) $(id).setAttribute("aria-pressed", String(view === id));
  render();
  const wanted = `${item.n} ${view}`;
  try {
    const evidence = await api(`evidence/${item.n}?view=${view}`);
    if (wanted !== `${items[current].n} ${view}`) return;
    let marked = null;
    for (const block of evidence.blocks) {
      const list = document.createElement("ol");
      list.className = "block";
      block.lines.forEach((text, index) => {
        const number = block.start + index;
        const row = document.createElement("li");
        const gutter = document.createElement("span");
        gutter.className = "number";
        gutter.textContent = String(number);
        const code = document.createElement("code");
        code.textContent = text;
        row.append(gutter, code);
        if (number === block.highlight) {
          row.className = "marked";
          row.setAttribute("aria-current", "true");
          marked = row;
        }
        list.append(row);
      });
      $("code").append(list);
    }
    $("code-note").textContent = evidence.note;
    readable = evidence.blocks.length > 0;
    $("code-retry").hidden = readable;
    marked?.scrollIntoView({ block: "center" });
  } catch (error) {
    $("code-note").textContent = `Codice non caricato: ${error.message}`;
    $("code-retry").hidden = false;
  }
  render();
}

function show(index, focus = true) {
  current = Math.max(0, Math.min(items.length - 1, index));
  view = "normal";
  const item = items[current];
  $("position").textContent = `Voce ${item.n} di ${items.length} · ${item.repository}`;
  $("title").textContent = `${item.rule} (${item.tool})`;
  $("where").textContent = `${item.path}:${item.line}`;
  $("message").textContent = item.message || "Messaggio del tool non disponibile.";
  $("clone").textContent = item.clone;
  $("note").value = state.notes[String(item.n)] ?? "";
  $("confirm").hidden = true;
  if (focus) $("title").focus();
  loadCode();
}

// Lascia la voce: salva il tempo passato e la nota.
function leave(index) {
  if (index < 0 || index >= items.length || index === current) return;
  save(items[current].n);
  show(index);
}

const firstUnanswered = (from) => {
  const order = [...items.keys()].map((i) => (i + from) % items.length);
  return order.find((i) => !state.labels[String(items[i].n)]);
};

function answer(label) {
  if (locked() || !readable) return;
  const n = items[current].n;
  const key = String(n);
  undoStep = { n, label: state.labels[key] ?? null };
  state.labels[key] = label;
  save(n);
  $("last").textContent = `Voce ${n}: ${NAMES[label]}.`;
  $("status").textContent = $("last").textContent;
  const next = firstUnanswered(current + 1);
  if (next === undefined) render();
  else show(next, false);
}

function undo() {
  if (locked() || !undoStep) return;
  const { n, label } = undoStep;
  undoStep = null;
  if (label) state.labels[String(n)] = label;
  else delete state.labels[String(n)];
  const index = items.findIndex((i) => i.n === n);
  if (index !== current) { save(items[current].n); show(index); }
  save(n);
  $("last").textContent = `Annullata la risposta alla voce ${n}.`;
  $("status").textContent = $("last").textContent;
  render();
}

for (const button of document.querySelectorAll("#answers button")) {
  button.addEventListener("click", () => answer(button.dataset.label));
}
for (const id of ["wide", "full"]) {
  $(id).addEventListener("click", () => { view = view === id ? "normal" : id; loadCode(); });
}
$("code-retry").addEventListener("click", loadCode);
$("previous").addEventListener("click", () => leave(current - 1));
$("next").addEventListener("click", () => leave(current + 1));
$("unanswered").addEventListener("click", () => leave(firstUnanswered(0) ?? current));
$("undo").addEventListener("click", undo);
$("alert-action").addEventListener("click", () => location.reload());
$("note").addEventListener("change", () => {
  const key = String(items[current].n);
  if ($("note").value.trim()) state.notes[key] = $("note").value;
  else delete state.notes[key];
  save(items[current].n);
});
$("deliver").addEventListener("click", () => { $("confirm").hidden = false; render(); $("confirm-no").focus(); });
$("confirm-no").addEventListener("click", () => { $("confirm").hidden = true; render(); $("deliver").focus(); });
$("confirm-yes").addEventListener("click", async () => {
  $("confirm").hidden = true;
  await save(items[current].n);
  if (broken) return;
  try {
    const done = await api("deliver", { method: "POST", body: JSON.stringify({ revision: state.revision }) });
    delivered = done.delivered;
    $("status").textContent = `Consegnato in golden-set/${delivered}.`;
  } catch (error) {
    stop(`Non consegnato: ${error.message}.`);
  }
  render();
});

const shortcuts = $("shortcuts");
shortcuts.checked = localStorage.getItem("shortcuts") === "on";
shortcuts.addEventListener("change", () => localStorage.setItem("shortcuts", shortcuts.checked ? "on" : "off"));
addEventListener("keydown", (event) => {
  if (!shortcuts.checked || event.ctrlKey || event.metaKey || event.altKey || event.repeat) return;
  if (event.target.closest("textarea, #code")) return;
  const label = { 1: "vero", 2: "falso-positivo", 3: "non-so" }[event.key];
  if (label) answer(label);
  else if (event.key === "ArrowLeft") leave(current - 1);
  else if (event.key === "ArrowRight") leave(current + 1);
  else if (event.key.toLowerCase() === "z") undo();
  else return;
  event.preventDefault();
});

api("sample").then((data) => {
  ({ items, state, delivered } = data);
  $("set").textContent = `· ${data.set} · ${data.annotator}, giro ${data.round}`;
  $("rules").open = answered() === 0;
  show(firstUnanswered(0) ?? 0, false);
}).catch((error) => stop(`Non riesco a caricare il campione: ${error.message}.`));

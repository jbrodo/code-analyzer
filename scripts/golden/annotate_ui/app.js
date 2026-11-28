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
let request = 0; // vale solo l'ultima richiesta di codice
let broken = false; // un salvataggio fallito ferma tutto
let queue = Promise.resolve(true);
let pendingSaves = 0;
const history = []; // risposte cambiate, per annullarle una alla volta
let spent = 0;
let tick = Date.now();
let lastActivity = Date.now();

async function api(path, options = {}) {
  let response;
  try {
    response = await fetch(`/api/${path}`, {
      ...options,
      headers: { "X-Token": token, "Content-Type": "application/json" },
    });
  } catch {
    throw new Error("il server non risponde: controlla che lo strumento sia ancora in esecuzione");
  }
  const data = await response.json();
  if (!response.ok) throw new Error(data.error ?? `errore ${response.status}`);
  return data;
}

function stop(message) {
  broken = true;
  $("alert-text").textContent = message;
  $("alert").hidden = false;
  render();
  $("alert-action").focus();
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

// Vero se la voce è stata salvata: solo allora la pagina lo può dire.
function save(n) {
  if (broken || delivered) return queue.then(() => false);
  const key = String(n);
  const body = { label: state.labels[key] ?? null, note: state.notes[key] ?? "", seconds: takeSeconds() };
  pendingSaves += 1;
  $("saved").textContent = "Salvataggio…";
  queue = queue.then(async () => {
    if (broken) return false;
    try {
      const done = await api(`item/${n}`, { method: "PUT", body: JSON.stringify({ ...body, revision: state.revision }) });
      state.revision = done.revision;
      pendingSaves -= 1;
      if (pendingSaves === 0) $("saved").textContent = "Salvato";
      return true;
    } catch (error) {
      $("saved").textContent = "Non salvato";
      $("last").textContent = "";
      $("status").textContent = "";
      stop(`Non salvato: ${error.message}. L'ultima modifica va rifatta.`);
      return false;
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
  $("undo").hidden = history.length === 0 || locked();
  $("delivery-text").textContent = delivered
    ? `Consegnato in golden-set/${delivered}.`
    : missing ? `Per consegnare mancano ${missing} risposte.` : "Tutte le voci hanno una risposta. Dopo la consegna non si modificano.";
  $("deliver").hidden = missing > 0 || locked() || !$("confirm").hidden;
}

// Scorre solo il riquadro del codice: la pagina resta dov'è.
function centreMarked() {
  const box = $("code");
  const row = box.querySelector(".marked");
  if (!row) return;
  const offset = row.getBoundingClientRect().top - box.getBoundingClientRect().top;
  box.scrollTop += offset - Math.max(0, (box.clientHeight - row.offsetHeight) / 2);
}

async function loadCode() {
  const item = items[current];
  const mine = ++request;
  readable = false;
  $("code").replaceChildren();
  $("code-note").textContent = "Carico il codice…";
  $("code-retry").hidden = true;
  for (const id of ["wide", "full"]) $(id).setAttribute("aria-pressed", String(view === id));
  render();
  try {
    const evidence = await api(`evidence/${item.n}?view=${view}`);
    if (mine !== request) return;
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
        }
        list.append(row);
      });
      $("code").append(list);
    }
    $("code-note").textContent = evidence.note;
    readable = evidence.blocks.length > 0;
    $("code-retry").hidden = readable;
    centreMarked();
  } catch (error) {
    if (mine !== request) return;
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
  $("last").textContent = ""; // niente della voce precedente accanto alle risposte di questa
  $("confirm").hidden = true;
  $("status").textContent = `Voce ${item.n} di ${items.length}: ${item.rule}, ${item.path}, riga ${item.line}.`;
  if (focus) $("title").focus();
  loadCode();
}

// Lascia la voce: salva il tempo passato e la nota.
function leave(index) {
  if (index < 0 || index >= items.length || index === current) return;
  save(items[current].n);
  show(index);
}

const firstUnanswered = () => items.findIndex((i) => !state.labels[String(i.n)]);

function jump() {
  const index = items.findIndex((i) => String(i.n) === $("jump").value.trim());
  if (index < 0) {
    $("status").textContent = `Le voci vanno da 1 a ${items.length}.`;
    $("last").textContent = $("status").textContent;
    return;
  }
  $("jump").value = "";
  leave(index);
}

function setLabel(key, label) {
  if (label) state.labels[key] = label;
  else delete state.labels[key];
}

// La risposta resta sulla voce: per passare oltre serve un gesto diverso.
async function answer(label) {
  if (locked() || !readable) return;
  const n = items[current].n;
  const key = String(n);
  const before = state.labels[key] ?? null;
  if (before === label) return; // ripetere la stessa risposta non cambia nulla
  setLabel(key, label);
  render();
  if (await save(n)) {
    history.push({ n, label: before });
    const missing = items.length - answered();
    const message = `Voce ${n}: ${NAMES[label]}, salvata.${missing ? "" : " Tutte le voci hanno una risposta."}`;
    $("status").textContent = message;
    if (items[current].n === n) $("last").textContent = message;
  } else {
    setLabel(key, before);
  }
  render();
}

async function undo() {
  if (locked() || history.length === 0) return;
  const { n, label } = history.pop();
  const key = String(n);
  const undone = state.labels[key] ?? null;
  const index = items.findIndex((i) => i.n === n);
  if (index !== current) { save(items[current].n); show(index); }
  setLabel(key, label);
  render();
  if (await save(n)) {
    const message = `Annullata l'ultima modifica alla voce ${n}.`;
    $("status").textContent = message;
    $("last").textContent = message;
  } else {
    setLabel(key, undone);
  }
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
$("unanswered").addEventListener("click", () => leave(firstUnanswered()));
$("jump-go").addEventListener("click", jump);
$("jump").addEventListener("keydown", (event) => { if (event.key === "Enter") jump(); });
$("to-marked").addEventListener("click", centreMarked);
$("show-rules").addEventListener("click", () => {
  $("rules").open = true;
  const summary = $("rules").querySelector("summary");
  summary.focus({ preventScroll: true });
  summary.scrollIntoView({ block: "start" });
});
$("undo").addEventListener("click", undo);
$("alert-action").addEventListener("click", () => location.reload());
$("note").addEventListener("change", () => {
  const key = String(items[current].n);
  if ($("note").value.trim()) state.notes[key] = $("note").value;
  else delete state.notes[key];
  save(items[current].n);
});
function closeConfirm() {
  $("confirm").hidden = true;
  render();
  $("deliver").focus();
}
$("deliver").addEventListener("click", () => { $("confirm").hidden = false; render(); $("confirm-no").focus(); });
$("confirm-no").addEventListener("click", closeConfirm);
$("confirm-yes").addEventListener("click", async () => {
  $("confirm").hidden = true;
  save(items[current].n);
  await queue;
  if (broken) return;
  try {
    const done = await api("deliver", { method: "POST", body: JSON.stringify({ revision: state.revision }) });
    delivered = done.delivered;
    $("status").textContent = `Consegnato in golden-set/${delivered}.`;
  } catch (error) {
    stop(`Non consegnato: ${error.message}.`);
    return;
  }
  render();
  $("delivery-text").focus();
});

// Un gesto, un'azione: né il secondo clic di un doppio clic né un tasto tenuto premuto ripetono.
for (const area of [$("actions"), $("delivery")]) {
  area.addEventListener("click", (event) => {
    if (event.detail > 1 && event.target.closest("button")) {
      event.preventDefault();
      event.stopImmediatePropagation();
    }
  }, { capture: true });
  area.addEventListener("keydown", (event) => {
    if (event.repeat && (event.key === "Enter" || event.key === " ") && event.target.closest("button")) event.preventDefault();
  }, { capture: true });
}
addEventListener("keydown", (event) => {
  if (event.key === "Escape" && !$("confirm").hidden) closeConfirm();
});

const shortcuts = $("shortcuts");
shortcuts.checked = localStorage.getItem("shortcuts") === "on";
shortcuts.addEventListener("change", () => localStorage.setItem("shortcuts", shortcuts.checked ? "on" : "off"));
addEventListener("keydown", (event) => {
  if (!shortcuts.checked || event.ctrlKey || event.metaKey || event.altKey || event.repeat) return;
  if (event.target.closest("textarea, input[type=number], #code")) return;
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
  $("jump").max = String(items.length);
  show(Math.max(0, firstUnanswered()), false);
}).catch((error) => stop(`Non riesco a caricare il campione: ${error.message}.`));

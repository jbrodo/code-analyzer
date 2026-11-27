"""Dashboard locale per la valutazione alla cieca di X-04 (protocollo in `doc/verifiche/gate-2.md`).

Il valutatore guarda un finding alla volta con il codice al commit scansionato, lo mette in un
gruppo di urgenza. Dentro un gruppo tutto parte alla pari, e si spostano in fasce solo i finding che
vengono prima o dopo gli altri. I numeri li calcola lo strumento e li scrive in
`ordinamento-<repo>.csv` alla consegna.

La consegna non si può modificare, quindi deve corrispondere a ciò che si è visto: ogni salvataggio
parte dalla revisione che la pagina ha davvero (un'altra scheda non sovrascrive in silenzio) e la
consegna vale solo per l'impronta del riepilogo mostrato.

Cieca per costruzione: legge **solo** `valutazione-<repo>.md` (senza livelli, severità, punteggi né
varianti), il proprio file di avanzamento e il codice con `git show`. Non apre mai i report, le
chiavi di corrispondenza né altri ordinamenti. Dopo la consegna l'ordine non si modifica.

    python3 scripts/gate2/review.py            # poi aprire l'indirizzo stampato

Solo libreria standard. Ascolta solo su 127.0.0.1; l'API chiede il segreto dell'indirizzo stampato
(nel frammento, che il browser non invia) e controlla l'intestazione `Host` (DNS rebinding). I
repository valutati sono riservati: la pagina non carica nulla da fuori.
"""

import argparse
import csv
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import threading
from datetime import UTC, datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

HERE = Path(__file__).resolve().parent
PAGES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/bands.js": ("bands.js", "text/javascript; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
}
PROTOCOL = HERE.parents[1] / "doc/verifiche/gate-2.md"
BUCKETS = (1, 2, 3, 4)
MAX_BODY = 64 * 1024
MAX_FILE = 2 * 1024 * 1024
MAX_NOTE = 1000
MAX_LINE = 400
MAX_FULL = 5000
MAX_TIER = 100
CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)


class ReviewError(Exception):
    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


# --- campione ------------------------------------------------------------------------------------

_ITEM = re.compile(r"^## (\d+)\. (.*)$", re.M)
_FIELDS = {"category": "Categoria", "rule": "Regola", "position": "Posizione"}


def parse_sample(text: str) -> list[dict[str, Any]]:
    """Le voci di `valutazione-<repo>.md`. Il messaggio è tutto ciò che segue la sua etichetta
    fino alla voce successiva: può andare a capo."""
    marks = list(_ITEM.finditer(text))
    items = []
    for index, mark in enumerate(marks):
        end = marks[index + 1].start() if index + 1 < len(marks) else len(text)
        block = text[mark.end() : end]
        item: dict[str, Any] = {"n": int(mark.group(1)), "title": mark.group(2).strip()}
        for key, label in _FIELDS.items():
            found = re.search(rf"^- {label}: (.*)$", block, re.M)
            item[key] = found.group(1).strip() if found else ""
        message = re.search(r"^- Messaggio: ", block, re.M)
        item["message"] = block[message.end() :].strip() if message else ""
        items.append(item)
    if not items or sorted(i["n"] for i in items) != list(range(1, len(items) + 1)):
        raise ReviewError("il file di valutazione non ha le voci numerate da 1", 500)
    return items


# --- ordinamento ---------------------------------------------------------------------------------


def clean_state(raw: Any, total: int) -> dict[str, Any]:
    """Lo stato inviato dalla pagina, ridotto a ciò che ha senso: il resto si rifiuta o si
    scarta. `tiers` è la fascia di un finding dentro il suo gruppo: 0 (assente) per i non spostati,
    negativa per chi viene prima di loro, positiva per chi viene dopo."""
    if not isinstance(raw, dict):
        raise ReviewError("stato non valido")
    valid = set(range(1, total + 1))

    def number(value: Any) -> int:
        if isinstance(value, bool) or not isinstance(value, int | str) or not str(value).isdigit():
            raise ReviewError("numero non valido")
        if int(value) not in valid:
            raise ReviewError("finding sconosciuto")
        return int(value)

    buckets, tiers, notes = {}, {}, {}
    for key, bucket in dict(raw.get("buckets") or {}).items():
        if isinstance(bucket, bool) or bucket not in BUCKETS:
            raise ReviewError("gruppo sconosciuto")
        buckets[str(number(key))] = int(bucket)
    for key, tier in dict(raw.get("tiers") or {}).items():
        if isinstance(tier, bool) or not isinstance(tier, int) or abs(tier) > MAX_TIER:
            raise ReviewError("fascia non valida")
        name = str(number(key))
        if tier and name in buckets:
            tiers[name] = tier
    for key, note in dict(raw.get("notes") or {}).items():
        if not isinstance(note, str) or len(note) > MAX_NOTE:
            raise ReviewError("nota non valida")
        if note.strip():
            notes[str(number(key))] = note
    return {"buckets": buckets, "tiers": tiers, "notes": notes}


def ranks(state: dict[str, Any], total: int) -> dict[int, int]:
    """Posizioni da 1, con i pari merito: contano solo il gruppo e la fascia. Chi sta nella stessa
    fascia è alla pari; né l'ordine dei voti né quello del campione diventano un giudizio."""
    missing = total - len(state["buckets"])
    if missing:
        raise ReviewError(f"mancano {missing} finding da classificare", 409)
    keys = {int(n): (b, state["tiers"].get(n, 0)) for n, b in state["buckets"].items()}
    ordered = sorted(keys.values())
    first = {}
    for index, key in enumerate(ordered, 1):
        first.setdefault(key, index)
    return {n: first[key] for n, key in keys.items()}


def csv_text(result: dict[int, int]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(["n", "rank"])
    writer.writerows([[n, result[n]] for n in sorted(result)])
    return buffer.getvalue()


# --- evidenze -----------------------------------------------------------------------------------

Span = tuple[int, int, int | None]  # prima riga, ultima riga, riga indicata


def _package_hits(lines: list[str], package: str, version: str) -> tuple[list[int], int]:
    """Le righe che nominano il pacchetto (non quelle che ne nominano uno dal nome più lungo):
    prima quelle con la versione segnalata nelle vicinanze. Secondo valore: quante hanno la
    versione."""
    name = re.compile(rf"(?<![\w.-]){re.escape(package)}(?![\w-]|\.\w)", re.I)
    hits = [i for i, text in enumerate(lines, 1) if name.search(text)]
    near = {i for i in hits if any(version in text for text in lines[i - 1 : i + 3])}
    return sorted(hits, key=lambda i: (i not in near, i)), len(near)


def _spans(lines: list[str], line: int | None, message: str, view: str) -> tuple[list[Span], list]:
    if view == "full":
        end = min(len(lines), MAX_FULL)
        note = [f"Mostrate le prime {end} righe di {len(lines)}."] if end < len(lines) else []
        return [(1, end, line if line and line <= end else None)], note
    before, after = (60, 90) if view == "wide" else (10, 25)
    if line is not None:
        if line > len(lines):
            note = f"La riga indicata ({line}) è oltre la fine del file ({len(lines)} righe)."
            return [(len(lines) - 44, len(lines), None)], [note]
        return [(line - before, line + after, line)], []
    start: Span = (1, 200 if view == "wide" else 45, None)
    package = re.search(r"Package '(@?[^@']+)@([^']+)'", message)
    if not package:
        return [start], ["Il finding non indica una riga: inizio del file."]
    hits, near = _package_hits(lines, package[1], package[2])
    if not hits:
        return [start], [f"Nessuna riga nomina «{package[1]}»: inizio del file."]
    shown = sorted(hits[: 20 if view == "wide" else 6])
    around = 8 if view == "wide" else 2
    note = f"Mostrati {len(shown)} punti su {len(hits)} che nominano «{package[1]}»"
    note += f"; per primi quelli vicini alla versione {package[2]}." if near else "."
    return [(i - around, i + around, i) for i in shown], [note]


# --- file ----------------------------------------------------------------------------------------


def _write(path: Path, data: str) -> None:
    handle, temporary = tempfile.mkstemp(dir=path.parent, prefix=".scrivo-")
    with os.fdopen(handle, "w", encoding="utf-8", newline="") as stream:
        stream.write(data)
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


class Review:
    """I campioni di una cartella di materiale, con il codice dei repository ai commit fissati."""

    def __init__(self, materials: Path, sources: dict[str, tuple[Path, str]]) -> None:
        self.materials = materials
        self.sources = sources
        self._writing = threading.Lock()

    def names(self) -> list[str]:
        return [n for n in self.sources if (self.materials / f"valutazione-{n}.md").is_file()]

    def _check(self, name: str) -> str:
        if name not in self.names():
            raise ReviewError("repository sconosciuto", 404)
        return name

    def items(self, name: str) -> list[dict[str, Any]]:
        path = self.materials / f"valutazione-{self._check(name)}.md"
        return parse_sample(path.read_text(encoding="utf-8"))

    def delivery(self, name: str) -> dict[str, Any] | None:
        path = self.materials / f"consegna-{self._check(name)}.json"
        return json.loads(path.read_text()) if path.is_file() else None

    def load(self, name: str) -> tuple[dict[str, Any], int]:
        """Solo l'avanzamento di questo strumento: un ordinamento già scritto non si ricarica."""
        path = self.materials / f"progresso-{self._check(name)}.json"
        total = len(self.items(name))
        raw = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
        return clean_state(raw, total), int(raw.get("revision", 0))

    def _open(self, name: str) -> None:
        if self.delivery(name) is not None:
            raise ReviewError("ordinamento già consegnato: non si modifica", 409)

    def save(self, name: str, raw: Any) -> dict[str, int]:
        """Salva solo se la pagina parte dall'ultima revisione: altrimenti qualcun altro (un'altra
        scheda) ha cambiato l'avanzamento, e sovrascriverlo perderebbe dei voti."""
        with self._writing:
            self._open(name)
            state = clean_state(raw, len(self.items(name)))
            current = self.load(name)[1]
            if type(raw.get("revision")) is not int or raw["revision"] != current:
                raise ReviewError("l'avanzamento è stato cambiato altrove: ricarica la pagina", 409)
            record = {"revision": current + 1, **state}
            _write(self.materials / f"progresso-{name}.json", json.dumps(record, indent=1))
            return {"revision": current + 1}

    def preview(self, name: str) -> dict[str, Any]:
        """Ciò che la consegna scriverebbe adesso, calcolato dallo stato salvato."""
        state, revision = self.load(name)
        result = ranks(state, len(self.items(name)))
        text = csv_text(result)
        return {
            "revision": revision,
            "state": state,
            "sha256": hashlib.sha256(text.encode()).hexdigest(),
            "rows": [{"n": n, "rank": r} for n, r in sorted(result.items(), key=lambda p: p[::-1])],
            "csv": text,
        }

    def deliver(self, name: str, revision: Any, sha256: Any) -> dict[str, Any]:
        with self._writing:
            self._open(name)
            shown = self.preview(name)
            if (revision, sha256) != (shown["revision"], shown["sha256"]):
                raise ReviewError(
                    "l'avanzamento è cambiato dopo il riepilogo: ricarica la pagina", 409
                )
            target = self.materials / f"ordinamento-{name}.csv"
            now = datetime.now(UTC)
            backup = None
            if target.is_file():
                with target.open(newline="") as stream:
                    written = any((r.get("rank") or "").strip() for r in csv.DictReader(stream))
                if written:  # non si sovrascrive nulla: ciò che c'era resta come copia
                    backup = f"ordinamento-{name}.prima-{now:%Y%m%dT%H%M%SZ}.csv"
                    _write(self.materials / backup, target.read_text(encoding="utf-8"))
            _write(target, shown["csv"])
            record = {
                "delivered_at": now.isoformat(timespec="seconds"),
                "sha256": shown["sha256"],
                "tool": "scripts/gate2/review.py",
                "previous": backup,
            }
            _write(self.materials / f"consegna-{name}.json", json.dumps(record, indent=1))
            return record

    # --- codice ----------------------------------------------------------------------------------

    def _file(self, name: str, path: str) -> list[str] | None:
        repository, commit = self.sources[name]
        done = subprocess.run(
            ["git", "-C", str(repository), "show", "--no-textconv", f"{commit}:{path}"],
            capture_output=True,
            check=False,
            timeout=30,
        )
        if done.returncode != 0 or len(done.stdout) > MAX_FILE or b"\x00" in done.stdout:
            return None
        return done.stdout.decode("utf-8", "replace").split("\n")

    def evidence(self, name: str, n: int, view: str = "normal") -> dict[str, Any]:
        item = next((i for i in self.items(name) if i["n"] == n), None)
        if item is None:
            raise ReviewError("finding sconosciuto", 404)
        # `percorso` oppure `percorso:riga`
        head, colon, tail = item["position"].rpartition(":")
        path, line = (head, int(tail)) if colon and tail.isdigit() else (item["position"], None)
        lines = self._file(name, path) if path and path != "—" else None
        if lines is None:
            note = "Codice non disponibile per questa posizione."
            return {"path": path, "blocks": [], "note": note}
        spans, notes = _spans(lines, line, item["message"], view)
        blocks, cut = [], False
        for first, last, mark in spans:
            first, last = max(1, first), min(len(lines), last)
            rows = lines[first - 1 : last]
            cut = cut or any(len(row) > MAX_LINE for row in rows)
            text = [row[:MAX_LINE] for row in rows]
            blocks.append({"start": first, "highlight": mark, "lines": text})
        if cut:
            notes.append(f"Le righe oltre {MAX_LINE} caratteri sono tagliate.")
        return {"path": path, "blocks": blocks, "note": " ".join(notes)}

    def summary(self) -> list[dict[str, Any]]:
        return [
            {
                "name": name,
                "total": len(self.items(name)),
                "assigned": len(self.load(name)[0]["buckets"]),
                "delivered": self.delivery(name) is not None,
            }
            for name in self.names()
        ]


# --- server --------------------------------------------------------------------------------------


def make_handler(review: Review, token: str) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:  # niente percorsi nei log
            pass

        def _send(self, status: int, body: bytes, kind: str) -> None:
            self.send_response(status)
            for header, value in (
                ("Content-Type", kind),
                ("Content-Length", str(len(body))),
                ("Content-Security-Policy", CSP),
                ("X-Content-Type-Options", "nosniff"),
                ("Referrer-Policy", "no-referrer"),
                ("Cache-Control", "no-store"),
            ):
                self.send_header(header, value)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, value: Any, status: int = 200) -> None:
            self._send(status, json.dumps(value).encode(), "application/json")

        def _guard(self) -> None:
            port = self.server.server_address[1]
            if self.headers.get("Host") not in (f"127.0.0.1:{port}", f"localhost:{port}"):
                raise ReviewError("host non ammesso", HTTPStatus.FORBIDDEN)

        def _body(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length") or 0)
            if not 0 < length <= MAX_BODY:
                raise ReviewError("richiesta troppo grande o vuota", 413)
            try:
                value = json.loads(self.rfile.read(length))
            except ValueError as exc:
                raise ReviewError("JSON non valido") from exc
            if not isinstance(value, dict):
                raise ReviewError("richiesta non valida")
            return value

        def _api(self, method: str) -> None:
            given = self.headers.get("X-Token", "")
            if not hmac.compare_digest(given.encode(), token.encode()):
                raise ReviewError("manca il segreto: aprire l'indirizzo stampato", 403)
            url = urlsplit(self.path)
            parts = url.path.strip("/").split("/")[1:]
            match (method, parts):
                case ("GET", ["repos"]):
                    self._json(review.summary())
                case ("GET", ["repo", name]):
                    state, revision = review.load(name)
                    self._json(
                        {
                            "items": review.items(name),
                            "state": state,
                            "revision": revision,
                            "delivery": review.delivery(name),
                        }
                    )
                case ("GET", ["evidence", name, n]) if n.isdigit():
                    view = parse_qs(url.query).get("view", ["normal"])[0]
                    self._json(review.evidence(name, int(n), view))
                case ("GET", ["preview", name]):
                    self._json(review.preview(name))
                case ("PUT", ["state", name]):
                    self._json(review.save(name, self._body()))
                case ("POST", ["deliver", name]):
                    body = self._body()
                    self._json(review.deliver(name, body.get("revision"), body.get("sha256")))
                case _:
                    raise ReviewError("risorsa sconosciuta", 404)

        def _handle(self, method: str) -> None:
            try:
                self._guard()
                path = urlsplit(self.path).path
                if path.startswith("/api/"):
                    self._api(method)
                elif method == "GET" and path in PAGES:
                    file, kind = PAGES[path]
                    self._send(200, (HERE / "review_ui" / file).read_bytes(), kind)
                else:
                    raise ReviewError("risorsa sconosciuta", 404)
            except ReviewError as exc:
                self._json({"error": str(exc)}, exc.status)
            except TypeError, ValueError, AttributeError:
                self._json({"error": "richiesta non valida"}, 400)

        def do_GET(self) -> None:
            self._handle("GET")

        def do_PUT(self) -> None:
            self._handle("PUT")

        def do_POST(self) -> None:
            self._handle("POST")

    return Handler


def protocol_commits(text: str) -> dict[str, str]:
    """I repository della tabella «Repository» del protocollo, con il commit fissato. Il file ha
    altre tabelle con dei commit (le PR di X-05): non contano."""
    table = re.search(r"^### Repository$(.*?)^###? ", text, re.M | re.S)
    if table is None:
        raise ReviewError("nel protocollo manca la tabella dei repository", 500)
    return dict(re.findall(r"^\| `([\w.-]+)` \| `([0-9a-f]{40})` \|", table[1], re.M))


def find_sources(
    materials: Path, commits: dict[str, str], chosen: dict[str, Path]
) -> tuple[dict[str, tuple[Path, str]], list[str]]:
    sources, problems = {}, []
    for name, commit in commits.items():
        candidates = [chosen[name]] if name in chosen else []
        candidates += [materials / "repos" / name, Path.home() / "git" / name]
        for path in candidates:
            done = subprocess.run(
                ["git", "-C", str(path), "cat-file", "-e", f"{commit}^{{commit}}"],
                capture_output=True,
                check=False,
            )
            if done.returncode == 0:
                sources[name] = (path, commit)
                break
        else:
            problems.append(f"{name}: nessun clone con il commit {commit[:7]} (--repo {name}=…)")
    return sources, problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--materials", type=Path, default=Path.home() / "gate2-material")
    parser.add_argument("--repo", action="append", default=[], metavar="NOME=PERCORSO")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args(argv)
    materials = args.materials.resolve()
    if HERE.parents[1] in materials.parents or materials == HERE.parents[1]:
        print("errore: il materiale sta fuori dal repository", file=sys.stderr)
        return 2
    chosen = {k: Path(v).expanduser() for k, _, v in (r.partition("=") for r in args.repo)}
    sources, problems = find_sources(materials, protocol_commits(PROTOCOL.read_text()), chosen)
    for problem in problems:
        print(f"avviso: {problem}", file=sys.stderr)
    review = Review(materials, sources)
    if not review.names():
        print("errore: nessun campione da valutare", file=sys.stderr)
        return 2
    token = secrets.token_urlsafe(24)
    server = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(review, token))
    print(f"Valutazione: http://127.0.0.1:{server.server_address[1]}/#t={token}", flush=True)
    print("Ctrl+C per chiudere. L'avanzamento si salva da sé.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())

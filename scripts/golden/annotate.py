"""Interfaccia locale per annotare il golden set (G3-03, ADR-0034).

    uv run python scripts/golden/annotate.py --set pilota --fetch   # poi aprire l'indirizzo

Chi annota vede un finding alla volta con il codice al commit del campione e risponde «vero»,
«falso positivo» o «non so». Nessun livello, nessun punteggio, nessuna proposta di un modello.
L'avanzamento e le note restano nel materiale locale, fuori dal repository. La consegna scrive in
`golden-set/` solo riferimenti e risposte, una volta sola.

Il codice mostrato è quello di repository pubblici non fidati: si legge con `git show` e la pagina
lo inserisce solo come testo. Il server ascolta su 127.0.0.1, chiede il segreto dell'indirizzo
stampato e controlla l'intestazione `Host`, come la dashboard del Gate 2 di cui riusa queste parti.
"""

import argparse
import hashlib
import hmac
import json
import os
import secrets
import subprocess
import sys
import threading
from collections import Counter
from datetime import UTC, datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, get_args
from urllib.parse import parse_qs, urlsplit

from ca_core.models.golden_set import GoldenLabels, GoldenSample, Label, SampleItem

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE.parent / "gate2"))

from review import CSP, MAX_BODY, MAX_FILE, MAX_LINE, MAX_NOTE, _spans, _write  # noqa: E402

PAGES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
}
LABELS = get_args(Label)
MAX_STEP = 3600  # secondi accettati in un solo salvataggio


class AnnotationError(Exception):
    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


def clone_name(url: str) -> str:
    owner, name = url.removeprefix("https://github.com/").split("/")
    return f"{owner}__{name}"


def has_commit(clone: Path, commit: str) -> bool:
    done = subprocess.run(
        ["git", "-C", str(clone), "cat-file", "-e", f"{commit}^{{commit}}"],
        capture_output=True,
        check=False,
    )
    return clone.is_dir() and done.returncode == 0


def fetch(clone: Path, url: str, commit: str) -> bool:
    """Scarica il solo commit, senza storia e senza file LFS. Niente di ciò che si scarica viene
    eseguito: gli hook di un repository remoto non si trasferiscono."""
    environment = {**os.environ, "GIT_LFS_SKIP_SMUDGE": "1", "GIT_TERMINAL_PROMPT": "0"}
    for command in (
        ["git", "init", "-q", str(clone)],
        ["git", "-C", str(clone), "fetch", "-q", "--depth", "1", url, commit],
        ["git", "-C", str(clone), "checkout", "-q", commit],
    ):
        if subprocess.run(command, env=environment, check=False).returncode != 0:
            return False
    return has_commit(clone, commit)


class Annotation:
    """Un giro di annotazione di un campione da parte di una persona."""

    def __init__(self, sample: Path, materials: Path, annotator: str, round_: int = 1) -> None:
        raw = sample.read_bytes()
        self.sample = GoldenSample.model_validate_json(raw)
        self.digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        self.annotator, self.round = annotator, round_
        self.clones = materials / "repos"
        suffix = f"{self.sample.set}.{annotator}.g{round_}"
        self.progress = materials / f"progresso-{suffix}.json"
        self.target = sample.parent / f"{self.sample.set}.labels.{annotator}.g{round_}.json"
        messages = materials / f"messaggi-{self.sample.set}.json"
        self.messages: dict[str, str] = (
            json.loads(messages.read_text(encoding="utf-8")) if messages.is_file() else {}
        )
        self._writing = threading.Lock()

    def item(self, n: int) -> SampleItem:
        if not 1 <= n <= len(self.sample.items):
            raise AnnotationError("voce sconosciuta", 404)
        return self.sample.items[n - 1]

    def state(self) -> dict[str, Any]:
        if not self.progress.is_file():
            return {"sample": self.digest, "revision": 0, "labels": {}, "notes": {}, "seconds": {}}
        state = json.loads(self.progress.read_text(encoding="utf-8"))
        if state["sample"] != self.digest:
            raise AnnotationError("l'avanzamento è di un altro campione: non lo uso", 409)
        return state

    def view(self) -> dict[str, Any]:
        items = []
        for n, item in enumerate(self.sample.items, 1):
            key = f"{item.repository} {item.fingerprint}"
            items.append(
                {
                    "n": n,
                    "repository": item.repository.removeprefix("https://github.com/"),
                    "tool": item.tool,
                    "rule": item.rule_id,
                    "path": item.path,
                    "line": item.start_line,
                    "message": self.messages.get(key, ""),
                    "clone": str(self.clones / clone_name(item.repository)),
                }
            )
        return {
            "set": self.sample.set,
            "annotator": self.annotator,
            "round": self.round,
            "items": items,
            "state": self.state(),
            "delivered": self.target.name if self.target.is_file() else None,
        }

    def save(self, n: int, body: dict[str, Any]) -> dict[str, Any]:
        """Aggiorna una voce. Salva solo se la pagina parte dall'ultima revisione: un'altra scheda
        non sovrascrive in silenzio."""
        self.item(n)
        label, note, spent = body.get("label"), body.get("note", ""), body.get("seconds", 0)
        if label is not None and label not in LABELS:
            raise AnnotationError("risposta sconosciuta")
        if not isinstance(note, str) or len(note) > MAX_NOTE:
            raise AnnotationError("nota non valida")
        if type(spent) is not int or not 0 <= spent <= MAX_STEP:
            raise AnnotationError("tempo non valido")
        with self._writing:
            if self.target.is_file():
                raise AnnotationError("già consegnato: non si modifica", 409)
            state = self.state()
            if type(body.get("revision")) is not int or body["revision"] != state["revision"]:
                raise AnnotationError("l'avanzamento è cambiato altrove: ricarica la pagina", 409)
            key = str(n)
            for field, value in (("labels", label), ("notes", note.strip() and note)):
                if value:
                    state[field][key] = value
                else:
                    state[field].pop(key, None)
            state["seconds"][key] = state["seconds"].get(key, 0) + spent
            state["revision"] += 1
            self.progress.parent.mkdir(parents=True, exist_ok=True)
            _write(self.progress, json.dumps(state, indent=1))
            return {"revision": state["revision"]}

    def deliver(self, revision: Any) -> dict[str, Any]:
        with self._writing:
            if self.target.is_file():
                raise AnnotationError("già consegnato: non si modifica", 409)
            state = self.state()
            if type(revision) is not int or revision != state["revision"]:
                raise AnnotationError("l'avanzamento è cambiato altrove: ricarica la pagina", 409)
            missing = len(self.sample.items) - len(state["labels"])
            if missing:
                raise AnnotationError(f"mancano {missing} risposte", 409)
            labels = GoldenLabels.model_validate(
                {
                    "version": 1,
                    "set": self.sample.set,
                    "sample_sha256": self.digest,
                    "annotator": self.annotator,
                    "round": self.round,
                    "delivered_at": datetime.now(UTC).replace(microsecond=0),
                    "labels": [
                        {
                            "repository": item.repository,
                            "fingerprint": item.fingerprint,
                            "label": state["labels"][str(n)],
                            "seconds": state["seconds"].get(str(n), 0),
                        }
                        for n, item in enumerate(self.sample.items, 1)
                    ],
                }
            )
            _write(self.target, labels.model_dump_json(indent=1) + "\n")
            os.chmod(self.target, 0o644)  # sta nel repository, a differenza dell'avanzamento
            return {
                "delivered": self.target.name,
                "counts": dict(Counter(label.label for label in labels.labels)),
            }

    def evidence(self, n: int, view: str = "normal") -> dict[str, Any]:
        item = self.item(n)
        done = subprocess.run(
            [
                "git",
                "-C",
                str(self.clones / clone_name(item.repository)),
                "show",
                "--no-textconv",
                f"{item.commit}:{item.path}",
            ],
            capture_output=True,
            check=False,
            timeout=30,
        )
        if done.returncode != 0 or len(done.stdout) > MAX_FILE or b"\x00" in done.stdout:
            return {"blocks": [], "note": "Codice non disponibile: manca la copia locale?"}
        lines = done.stdout.decode("utf-8", "replace").split("\n")
        spans, notes = _spans(lines, item.start_line, "", view)
        blocks, cut = [], False
        for first, last, mark in spans:
            first, last = max(1, first), min(len(lines), last)
            rows = lines[first - 1 : last]
            cut = cut or any(len(row) > MAX_LINE for row in rows)
            blocks.append(
                {"start": first, "highlight": mark, "lines": [row[:MAX_LINE] for row in rows]}
            )
        if cut:
            notes.append(f"Le righe oltre {MAX_LINE} caratteri sono tagliate.")
        return {"blocks": blocks, "note": " ".join(notes)}


def make_handler(annotation: Annotation, token: str) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
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

        def _body(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length") or 0)
            if not 0 < length <= MAX_BODY:
                raise AnnotationError("richiesta troppo grande o vuota", 413)
            value = json.loads(self.rfile.read(length))
            if not isinstance(value, dict):
                raise AnnotationError("richiesta non valida")
            return value

        def _api(self, method: str) -> None:
            given = self.headers.get("X-Token", "")
            if not hmac.compare_digest(given.encode(), token.encode()):
                raise AnnotationError("manca il segreto: aprire l'indirizzo stampato", 403)
            url = urlsplit(self.path)
            match (method, url.path.strip("/").split("/")[1:]):
                case ("GET", ["sample"]):
                    self._json(annotation.view())
                case ("GET", ["evidence", n]) if n.isdigit():
                    view = parse_qs(url.query).get("view", ["normal"])[0]
                    self._json(annotation.evidence(int(n), view))
                case ("PUT", ["item", n]) if n.isdigit():
                    self._json(annotation.save(int(n), self._body()))
                case ("POST", ["deliver"]):
                    self._json(annotation.deliver(self._body().get("revision")))
                case _:
                    raise AnnotationError("risorsa sconosciuta", 404)

        def _handle(self, method: str) -> None:
            try:
                port = self.server.server_address[1]
                if self.headers.get("Host") not in (f"127.0.0.1:{port}", f"localhost:{port}"):
                    raise AnnotationError("host non ammesso", HTTPStatus.FORBIDDEN)
                path = urlsplit(self.path).path
                if path.startswith("/api/"):
                    self._api(method)
                elif method == "GET" and path in PAGES:
                    file, kind = PAGES[path]
                    self._send(200, (HERE / "annotate_ui" / file).read_bytes(), kind)
                else:
                    raise AnnotationError("risorsa sconosciuta", 404)
            except AnnotationError as exc:
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--set", dest="name", required=True)
    parser.add_argument("--annotator", default="annotatore-1")
    parser.add_argument("--round", type=int, default=1)
    parser.add_argument("--materials", type=Path, default=Path.home() / "golden-material")
    parser.add_argument("--fetch", action="store_true", help="scarica le copie che mancano")
    parser.add_argument("--port", type=int, default=8766)
    args = parser.parse_args(argv)
    materials = args.materials.resolve()
    if materials.is_relative_to(ROOT):
        print("errore: il materiale sta fuori dal repository", file=sys.stderr)
        return 2
    try:
        annotation = Annotation(
            ROOT / "golden-set" / f"{args.name}.sample.json", materials, args.annotator, args.round
        )
        annotation.state()
    except (OSError, ValueError, AnnotationError) as error:
        print(f"errore: {error}", file=sys.stderr)
        return 2
    wanted = {(i.repository, i.commit) for i in annotation.sample.items}
    missing = 0
    for url, commit in sorted(wanted):
        clone = materials / "repos" / clone_name(url)
        if has_commit(clone, commit):
            continue
        if args.fetch:
            print(f"scarico {url}", flush=True)
            if fetch(clone, url, commit):
                continue
        missing += 1
        print(f"avviso: manca la copia di {url} al commit {commit[:12]}", file=sys.stderr)
    if missing:
        print("errore: senza il codice non si annota (usare --fetch)", file=sys.stderr)
        return 2
    if not annotation.messages:
        print("avviso: mancano i messaggi dei tool (li scrive sample.py)", file=sys.stderr)
    token = secrets.token_urlsafe(24)
    server = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(annotation, token))
    print(f"Annotazione: http://127.0.0.1:{server.server_address[1]}/#t={token}", flush=True)
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

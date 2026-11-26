"""La SPA servita dallo stesso processo dell'API (I-03, ADR-0016, ADR-0030).

Con `CA_API_WEB_DIR` il server serve i file compilati di `web/` e, per ogni indirizzo che non è un
file e non sta sotto `/v1`, `index.html` (le viste hanno indirizzi propri, come
`/r/{repository}`). Senza, non aggiunge nulla e l'API resta com'era.

Scelte di sicurezza:
- Un file si serve solo se sta, già risolto, dentro la cartella e non è un collegamento che ne esce;
  `..`, byte nulli e percorsi lunghi sono 404. Nessun elenco di cartelle.
- Un indirizzo con estensione che non esiste è 404: non si risponde con HTML a uno script mancante.
- `/config.json` viene dal file indicato da `CA_API_WEB_CONFIG` (la configurazione dell'ambiente:
  l'IdP e il client OIDC, nessun segreto) e mai dalla cache.
- `Content-Security-Policy`: script e stili solo di questa origine (gli stili che la SPA inietta
  portano il nonce nuovo di ogni risposta di `index.html`), connessioni solo a questa origine e alle
  origini di `CA_API_CSP_CONNECT` (l'IdP), nessun frame, nessun `Referer`.
"""

import secrets
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, Response

from ca_api.config import Settings
from ca_api.problem import ApiProblem, ProblemCode

MAX_PATH = 300
IMMUTABLE = "public, max-age=31536000, immutable"  # i file di `assets/` hanno l'impronta nel nome


NONCE_PLACEHOLDER = b"__CSP_NONCE__"


def security_headers(settings: Settings, nonce: str | None = None) -> dict[str, str]:
    connect = " ".join(("'self'", *settings.csp_connect))
    style = "style-src 'self'" + (f" 'nonce-{nonce}'" if nonce else "")
    policy = "; ".join(
        (
            "default-src 'none'",
            "script-src 'self'",
            style,
            "img-src 'self' data:",
            "font-src 'self'",
            f"connect-src {connect}",
            "base-uri 'none'",
            "form-action 'self'",
            "frame-ancestors 'none'",
        )
    )
    return {
        "Content-Security-Policy": policy,
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "X-Frame-Options": "DENY",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    }


def _inside(root: Path, requested: str) -> Path | None:
    """Il file regolare a cui porta `requested`, se sta dentro `root`; altrimenti `None`."""
    if not requested or len(requested) > MAX_PATH or "\x00" in requested or "\\" in requested:
        return None
    candidate = (root / requested).resolve()
    if not candidate.is_relative_to(root) or not candidate.is_file():
        return None
    return candidate


def mount_spa(app: FastAPI, settings: Settings) -> None:
    if settings.web_dir is None:
        return
    root = Path(settings.web_dir).resolve()
    index = root / "index.html"
    if not index.is_file():
        raise ValueError("CA_API_WEB_DIR non contiene index.html")
    config = Path(settings.web_config).resolve() if settings.web_config else root / "config.json"
    headers = security_headers(settings)
    page = index.read_bytes()

    def send(path: Path, cache: str) -> Response:
        return FileResponse(path, headers={**headers, "Cache-Control": cache})

    def send_index() -> Response:
        # Un nonce nuovo a ogni risposta: lo stile che la SPA inietta (lo scorrimento bloccato sotto
        # un dialogo) lo porta e la politica non ha bisogno di `unsafe-inline`.
        nonce = secrets.token_urlsafe(16)
        body = page.replace(NONCE_PLACEHOLDER, nonce.encode())
        return Response(
            body,
            media_type="text/html; charset=utf-8",
            headers={**security_headers(settings, nonce), "Cache-Control": "no-store"},
        )

    @app.get("/{path:path}", include_in_schema=False)
    async def spa(path: str, request: Request) -> Response:  # noqa: ARG001
        if path == "v1" or path.startswith("v1/"):
            raise ApiProblem(404, ProblemCode.NOT_FOUND)  # l'API non risponde con la SPA
        if path == "config.json":
            if not config.is_file():
                raise ApiProblem(404, ProblemCode.NOT_FOUND)
            return send(config, "no-store")
        found = _inside(root, path)
        if found is not None:
            return send(found, IMMUTABLE if path.startswith("assets/") else "no-cache")
        if "." in path.rsplit("/", 1)[-1]:
            raise ApiProblem(404, ProblemCode.NOT_FOUND)  # uno script o un'immagine mancante
        return send_index()

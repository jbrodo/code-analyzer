"""Comando `upload` (L-03, ADR-0016, ADR-0019): invia gli artefatti di `scan` al server.

Facoltativo: senza `upload` la CLI funziona come prima. Nessun segreto a lunga durata: il token è
l'OIDC del provider CI, preso dall'ambiente (`CA_OIDC_TOKEN`, per GitLab `id_tokens`) oppure
richiesto a GitHub Actions con il suo endpoint (`ACTIONS_ID_TOKEN_REQUEST_URL`). Il token non è mai
un flag, non compare in nessun messaggio e va solo all'indirizzo del server, che non segue
redirect. Exit 0 inviato (anche se già presente), 2 errore. Mai 1.

Il report è l'unica parte obbligatoria; SARIF, SBOM e grafo si inviano se i file ci sono accanto.
`CA_UPLOAD_ALLOW_LOOPBACK_HTTP=1` ammette `http` su loopback (solo prove con un server finto).
"""

import argparse
import json
import os
import secrets
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

from ca_cli.composition import Context
from ca_cli.gate import _read_report
from ca_cli.scan import GRAPH_FILE, REPORT_FILE, ScanError
from ca_core.pipeline.publish import SARIF_NAME
from ca_integrations.github.transport import (
    TransportError,
    UrllibTransport,
    check_base_url,
)

MAX_PART_BYTES = 50 * 1024 * 1024
SBOM_FILE = "code-analyzer.sbom.json"
TOKEN_VARIABLE = "CA_OIDC_TOKEN"  # noqa: S105 - nome della variabile, non un segreto
UPLOAD_TIMEOUT = 60.0
_PARTS = (("sarif", SARIF_NAME), ("sbom", SBOM_FILE), ("graph", GRAPH_FILE))


def _token(env: Mapping[str, str], audience: str, context: Context) -> str:
    direct = env.get(TOKEN_VARIABLE, "")
    if direct:
        return direct
    url, request_token = (
        env.get("ACTIONS_ID_TOKEN_REQUEST_URL"),
        env.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN"),
    )
    if not url or not request_token:
        raise ScanError(f"token OIDC non disponibile: imposta {TOKEN_VARIABLE} o abilita id-token")
    parts = urlsplit(url)
    if parts.scheme != "https" and not _loopback_allowed(env, url):
        raise ScanError("endpoint del token OIDC non ammesso")
    separator = "&" if parts.query else "?"
    transport = context.notify_transport or UrllibTransport()
    try:
        reply = transport.request(
            "GET",
            f"{url}{separator}audience={quote(audience, safe='')}",
            {"Authorization": f"Bearer {request_token}", "Accept": "application/json"},
            None,
            15.0,
        )
        value = json.loads(reply.body).get("value") if reply.status == 200 else None
    except (TransportError, ValueError, AttributeError):
        value = None
    if not isinstance(value, str) or not value:
        raise ScanError("richiesta del token OIDC non riuscita")
    return value


def _loopback_allowed(env: Mapping[str, str], url: str) -> bool:
    try:
        check_base_url(url, allow_loopback_http=env.get("CA_UPLOAD_ALLOW_LOOPBACK_HTTP") == "1")
    except ValueError:
        return False
    return True


def _read_part(path: Path) -> bytes | None:
    try:
        with path.open("rb") as handle:
            data = handle.read(MAX_PART_BYTES + 1)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ScanError(f"{path.name}: non leggibile") from exc
    if len(data) > MAX_PART_BYTES:
        raise ScanError(f"{path.name}: troppo grande")
    return data


def multipart(parts: Mapping[str, tuple[str, bytes]]) -> tuple[bytes, str]:
    boundary = "ca-" + secrets.token_hex(16)
    out = bytearray()
    for name, (filename, data) in parts.items():
        out += f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"; '.encode()
        out += f'filename="{filename}"\r\nContent-Type: application/json\r\n\r\n'.encode()
        out += data + b"\r\n"
    out += f"--{boundary}--\r\n".encode()
    return bytes(out), f"multipart/form-data; boundary={boundary}"


def handle(args: argparse.Namespace, context: Context) -> int:
    env = dict(os.environ)
    report_path = Path(args.report)
    _read_report(report_path)  # validato come da `gate`: un report non valido non parte
    try:
        base = check_base_url(
            args.server, allow_loopback_http=env.get("CA_UPLOAD_ALLOW_LOOPBACK_HTTP") == "1"
        )
    except ValueError as exc:
        raise ScanError(f"server non valido: {exc}") from exc
    report = _read_part(report_path)
    assert report is not None
    parts: dict[str, tuple[str, bytes]] = {"report": (REPORT_FILE, report)}
    for name, filename in _PARTS:
        data = _read_part(report_path.parent / filename)
        if data is not None:
            parts[name] = (filename, data)
    token = _token(env, args.audience, context)
    body, content_type = multipart(parts)
    transport = context.notify_transport or UrllibTransport()
    try:
        reply = transport.request(
            "POST",
            f"{base}/v1/scans",
            {
                "Authorization": f"Bearer {token}",
                "Content-Type": content_type,
                "Accept": "application/json",
            },
            body,
            UPLOAD_TIMEOUT,
        )
    except TransportError as exc:
        raise ScanError("invio non riuscito: server non raggiungibile") from exc
    if reply.status in (200, 201):
        try:
            scan_id = str(json.loads(reply.body)["id"])
        except (ValueError, KeyError, TypeError):
            scan_id = "?"
        print(
            f"upload: {'inviata' if reply.status == 201 else 'già presente'} (scansione {scan_id})"
        )
        return 0
    print(f"code-analyzer: upload: {_refusal(reply.status, reply.body)}", file=sys.stderr)
    return 2


def _refusal(status: int, body: bytes) -> str:
    """Il solo codice del problema (`code`), mai il testo ricevuto."""
    try:
        code = json.loads(body).get("code")
    except (ValueError, AttributeError):
        code = None
    safe = (
        code
        if isinstance(code, str) and code.replace("-", "").isalnum() and len(code) < 60
        else "?"
    )
    return f"rifiutato dal server ({status}, {safe})"


def add_parser(commands: Any) -> None:
    parser = commands.add_parser("upload", help="invia il report al server (facoltativo)")
    parser.add_argument("--server", required=True, help="indirizzo https del server")
    parser.add_argument("--report", default=REPORT_FILE, help="report di `scan`")
    parser.add_argument(
        "--audience", default="code-analyzer", help="audience del token OIDC (GitHub Actions)"
    )

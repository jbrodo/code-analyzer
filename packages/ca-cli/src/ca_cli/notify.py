"""Comando `notify` (ADR-0027): commento sulla PR e check run di GitHub dal report di `scan`.

Non decide nulla: l'esito di una pipeline resta di `gate`. Exit 0 fatto, o saltato con avviso;
2 errore. Mai 1. Con un permesso mancante (token di sola lettura, tipico di una PR da fork) il
contenuto del commento va nel riepilogo del job, se l'ambiente ne ha uno, e l'exit è 0.

Il token viene solo dall'ambiente (`GITHUB_TOKEN`), mai da un flag, e non compare in nessun
messaggio. Repository, numero della PR e commit di testa vengono dai flag o dall'ambiente del
runner (`GITHUB_REPOSITORY`, file di `GITHUB_EVENT_PATH`); sono input non fidati e si validano.
`CA_NOTIFY_ALLOW_LOOPBACK_HTTP=1` ammette `http` su loopback (solo per le prove con un server
finto: il token non lascia la macchina). Un solo commento per PR (marcatore) e una check run per
esecuzione, sul commit di testa.
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

from ca_cli.composition import Context
from ca_cli.gate import _read_report
from ca_cli.scan import REPORT_FILE, ScanError
from ca_core.pipeline.gate import evaluate_gate
from ca_integrations import limits
from ca_integrations.github import GitHubClient, GitHubError
from ca_integrations.github.client import API_URL, DEFAULT_AUTHOR
from ca_integrations.github.format import build_check_run, build_comment

MAX_EVENT_BYTES = 5 * 1024 * 1024
MAX_SUMMARY_BYTES = 1024 * 1024
_REPO = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
_SHA = re.compile(r"^[0-9a-f]{40}$")
_AUTHOR = re.compile(r"^[A-Za-z0-9\[\]_.-]{1,100}$")


def parse_count(value: str) -> int:
    if not value.isascii() or not value.isdigit() or int(value) > 1000:
        raise argparse.ArgumentTypeError("intero tra 0 e 1000")
    return int(value)


def _event(env: dict[str, str]) -> dict[str, Any]:
    path = env.get("GITHUB_EVENT_PATH")
    if not path:
        return {}
    try:
        with Path(path).open("rb") as handle:
            data = handle.read(MAX_EVENT_BYTES + 1)
        parsed = json.loads(data) if len(data) <= MAX_EVENT_BYTES else {}
    except (OSError, ValueError, RecursionError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _from_event(event: dict[str, Any]) -> tuple[int | None, str | None]:
    pull = event.get("pull_request")
    if not isinstance(pull, dict):
        return None, None
    number, head = pull.get("number"), pull.get("head")
    sha = head.get("sha") if isinstance(head, dict) else None
    return (
        number
        if isinstance(number, int) and not isinstance(number, bool) and number >= 1
        else None,
        sha if isinstance(sha, str) and _SHA.fullmatch(sha) else None,
    )


def _summary(env: dict[str, str], text: str) -> bool:
    path = env.get("GITHUB_STEP_SUMMARY")
    if not path:
        return False
    try:
        with Path(path).open("ab") as handle:
            handle.write(text.encode()[:MAX_SUMMARY_BYTES])
    except OSError:
        return False
    return True


def handle(args: argparse.Namespace, context: Context) -> int:
    env = dict(os.environ)
    report = _read_report(Path(args.report))
    token = env.get("GITHUB_TOKEN", "")
    if not token:
        raise ScanError("GITHUB_TOKEN non impostato")
    repo = args.repo or env.get("GITHUB_REPOSITORY", "")
    if not _REPO.fullmatch(repo):
        raise ScanError("repository non valido: atteso proprietario/nome (--repo)")
    number, head_sha = _from_event(_event(env))
    number = args.pull_request or report.scan.pull_request or number
    head_sha = args.head_sha or head_sha
    if head_sha is not None and not _SHA.fullmatch(head_sha):
        head_sha = (
            None  # un valore malformato vale come assente: errore sotto, prima di ogni richiesta
        )
    if args.comment and number is None:
        raise ScanError("numero della PR sconosciuto (--pull-request)")
    if args.check_run and head_sha is None:
        raise ScanError("commit di testa sconosciuto (--head-sha)")
    if not _AUTHOR.fullmatch(args.author):
        raise ScanError("autore atteso non valido")
    try:
        client = GitHubClient(
            token,
            api_url=env.get("GITHUB_API_URL", API_URL),
            author=args.author,
            transport=context.notify_transport,
            allow_loopback_http=env.get("CA_NOTIFY_ALLOW_LOOPBACK_HTTP") == "1",
        )
    except ValueError as exc:
        raise ScanError(f"configurazione di GitHub non valida: {exc}") from exc

    gate = evaluate_gate(report)  # la stessa funzione di `gate`: una sola regola (ADR-0027)
    comment = build_comment(report, max_findings=args.max_findings, gate=gate)
    failed = False
    if args.comment:
        assert number is not None
        failed |= _attempt(
            "commento", lambda: client.upsert_comment(repo, number, comment), env, comment.body
        )
    if args.check_run:
        assert head_sha is not None
        check = build_check_run(report, max_annotations=args.max_annotations, gate=gate)
        failed |= _attempt(
            "check run", lambda: client.create_check_run(repo, head_sha, check), env, None
        )
    return 2 if failed else 0


def _attempt(what: str, call: Any, env: dict[str, str], fallback: str | None) -> bool:
    """True se è fallito in modo da far uscire con 2; un permesso mancante degrada con avviso."""
    try:
        call()
    except GitHubError as exc:
        if exc.code == "forbidden":
            kept = fallback is not None and _summary(env, fallback)
            note = "contenuto nel riepilogo del job" if kept else "nessun riepilogo disponibile"
            print(f"code-analyzer: notify: {what} non permesso ({note})", file=sys.stderr)
            return False
        print(f"code-analyzer: notify: {what}: {exc.code}", file=sys.stderr)
        return True
    print(f"notify: {what} aggiornato")
    return False


def add_parser(commands: Any) -> None:
    parser = commands.add_parser("notify", help="commento e check run sulla PR (GitHub)")
    parser.add_argument("--provider", choices=["github"], required=True)
    parser.add_argument("--report", default=REPORT_FILE, help="report di `scan`")
    parser.add_argument("--repo", help="proprietario/nome (predefinito: GITHUB_REPOSITORY)")
    parser.add_argument("--pull-request", type=_positive, help="numero della PR")
    parser.add_argument("--head-sha", help="commit di testa della PR, 40 cifre esadecimali")
    parser.add_argument("--author", default=DEFAULT_AUTHOR, help="identità che scrive il commento")
    parser.add_argument("--no-comment", dest="comment", action="store_false")
    parser.add_argument("--no-check-run", dest="check_run", action="store_false")
    parser.add_argument("--max-findings", type=parse_count, default=limits.DEFAULT_COMMENT_FINDINGS)
    parser.add_argument("--max-annotations", type=parse_count, default=limits.DEFAULT_ANNOTATIONS)


def _positive(value: str) -> int:
    if not value.isascii() or not value.isdigit() or not 1 <= int(value) <= 2_147_483_647:
        raise argparse.ArgumentTypeError("intero positivo")
    return int(value)

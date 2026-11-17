"""Client GitHub per il commento sulla PR e la check run (N-02, ADR-0027).

Solo il token del job: nessun token personale, nessuna App. Permessi minimi (ADR-0027):
`pull-requests: write` per il commento, `checks: write` per la check run. Con un permesso
mancante la chiamata dà `GitHubError("forbidden")` e il chiamante (`notify`) degrada con un
avviso: **un provider irraggiungibile non cambia mai l'esito del gate**.

- **Un solo commento per PR.** Si cerca tra i commenti quello che inizia con il marcatore *e* è
  scritto dall'identità attesa (`author`): un commento altrui con lo stesso marcatore si ignora
  (ADR-0027). Con il token del job l'identità non si può chiedere all'API, quindi la dà chi chiama
  (predefinito `github-actions[bot]`).
- **Il token** sta solo nell'intestazione `Authorization`. Non compare in `repr`, negli errori né
  nei messaggi; il corpo di una risposta d'errore non viene mai riportato.
- Nessun nuovo tentativo e nessuna attesa: una richiesta, una risposta, un esito.
"""

import json
import re
from dataclasses import dataclass

from ca_integrations.github.transport import (
    DEFAULT_TIMEOUT,
    Response,
    Transport,
    TransportError,
    UrllibTransport,
    check_base_url,
)
from ca_integrations.models import CheckRun, PullRequestComment

API_URL = "https://api.github.com"
API_VERSION = "2022-11-28"
DEFAULT_AUTHOR = "github-actions[bot]"
CHECK_NAME = "Code Analyzer"
PER_PAGE = 100
MAX_PAGES = 20  # 2000 commenti: oltre, il commento si crea nuovo invece di cercare all'infinito
_REPO = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
_SHA = re.compile(r"^[0-9a-f]{40}$")


class GitHubError(Exception):
    """Esito non riuscito. `code` è stabile per le macchine; il messaggio non ha mai dati."""

    CODES = (
        "unauthorized", "forbidden", "not-found", "validation", "rate-limited",
        "redirect", "server", "network", "bad-response", "client-error",
    )  # fmt: skip

    def __init__(self, code: str, status: int | None = None) -> None:
        super().__init__(f"GitHub: {code}" + (f" ({status})" if status is not None else ""))
        self.code = code
        self.status = status


@dataclass(frozen=True)
class CommentResult:
    id: int
    created: bool


def _classify(response: Response) -> GitHubError | None:
    status = response.status
    if 200 <= status < 300:
        return None
    if status in (301, 302, 303, 307, 308):
        return GitHubError("redirect", status)
    if status == 401:
        return GitHubError("unauthorized", status)
    if status == 403:
        remaining = response.headers.get("x-ratelimit-remaining")
        limited = remaining == "0" or "retry-after" in response.headers
        return GitHubError("rate-limited" if limited else "forbidden", status)
    if status == 404:
        return GitHubError("not-found", status)
    if status == 429:
        return GitHubError("rate-limited", status)
    if status in (409, 422):
        return GitHubError("validation", status)
    if status >= 500:
        return GitHubError("server", status)
    return GitHubError("client-error", status)


class GitHubClient:
    def __init__(
        self,
        token: str,
        *,
        api_url: str = API_URL,
        author: str = DEFAULT_AUTHOR,
        transport: Transport | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        allow_loopback_http: bool = False,
    ) -> None:
        if not token or any(c in token for c in "\r\n\x00 "):
            raise ValueError("token non valido")
        self.__token = token
        self._base = check_base_url(api_url, allow_loopback_http=allow_loopback_http)
        self._author = author
        self._transport = transport or UrllibTransport()
        self._timeout = timeout

    def __repr__(self) -> str:
        return f"GitHubClient(api_url={self._base!r}, author={self._author!r})"

    # --- richieste -------------------------------------------------------------------------------

    def _send(self, method: str, path: str, payload: object | None = None) -> object:
        headers = {
            "Authorization": f"Bearer {self.__token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": "code-analyzer",
        }
        body = None
        if payload is not None:
            body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
            headers["Content-Type"] = "application/json"
        try:
            response = self._transport.request(
                method, self._base + path, headers, body, self._timeout
            )
        except TransportError as exc:
            raise GitHubError("network") from exc
        error = _classify(response)
        if error is not None:
            raise error
        try:
            return json.loads(response.body) if response.body else None
        except (ValueError, RecursionError) as exc:
            raise GitHubError("bad-response", response.status) from exc

    @staticmethod
    def _repo(repo: str) -> str:
        if not _REPO.fullmatch(repo):
            raise ValueError("repository non valido: atteso proprietario/nome")
        return repo

    # --- commento ---------------------------------------------------------------------------------

    def find_comment(self, repo: str, pull_request: int, marker: str) -> int | None:
        """Identificativo del commento della PR che inizia con `marker` ed è dell'autore atteso."""
        self._repo(repo)
        if pull_request < 1:
            raise ValueError("numero della PR non valido")
        for page in range(1, MAX_PAGES + 1):
            path = f"/repos/{repo}/issues/{pull_request}/comments?per_page={PER_PAGE}&page={page}"
            items = self._send("GET", path)
            if not isinstance(items, list):
                raise GitHubError("bad-response")
            for item in items:
                if not isinstance(item, dict):
                    continue
                user = item.get("user")
                login = user.get("login") if isinstance(user, dict) else None
                body, ident = item.get("body"), item.get("id")
                if (
                    login == self._author
                    and isinstance(body, str)
                    and body.startswith(marker)
                    and isinstance(ident, int)
                    and not isinstance(ident, bool)
                ):
                    return ident
            if len(items) < PER_PAGE:
                break
        return None

    def upsert_comment(
        self, repo: str, pull_request: int, comment: PullRequestComment
    ) -> CommentResult:
        """Aggiorna il commento di Code Analyzer sulla PR, o lo crea se non c'è."""
        existing = self.find_comment(repo, pull_request, comment.marker)
        if existing is not None:
            self._send("PATCH", f"/repos/{repo}/issues/comments/{existing}", {"body": comment.body})
            return CommentResult(existing, created=False)
        created = self._send(
            "POST", f"/repos/{repo}/issues/{pull_request}/comments", {"body": comment.body}
        )
        ident = created.get("id") if isinstance(created, dict) else None
        if not isinstance(ident, int) or isinstance(ident, bool):
            raise GitHubError("bad-response")
        return CommentResult(ident, created=True)

    # --- check run --------------------------------------------------------------------------------

    def create_check_run(
        self, repo: str, head_sha: str, check: CheckRun, *, name: str = CHECK_NAME
    ) -> int:
        """Crea una check run già conclusa sul commit di testa della PR (ADR-0027)."""
        self._repo(repo)
        if not _SHA.fullmatch(head_sha):
            raise ValueError("commit non valido: 40 cifre esadecimali minuscole")
        output: dict[str, object] = {"title": check.output.title, "summary": check.output.summary}
        if check.output.annotations:
            output["annotations"] = [
                {
                    "path": a.path,
                    "start_line": a.start_line,
                    "end_line": a.end_line,
                    "annotation_level": a.level.value,
                    "title": a.title,
                    "message": a.message,
                }
                for a in check.output.annotations
            ]
        payload = {
            "name": name,
            "head_sha": head_sha,
            "status": "completed",
            "conclusion": check.conclusion.value,
            "output": output,
        }
        created = self._send("POST", f"/repos/{repo}/check-runs", payload)
        ident = created.get("id") if isinstance(created, dict) else None
        if not isinstance(ident, int) or isinstance(ident, bool):
            raise GitHubError("bad-response")
        return ident

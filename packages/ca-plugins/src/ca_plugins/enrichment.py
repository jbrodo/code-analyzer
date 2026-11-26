"""Sincronizzazione e cache dei feed EPSS e KEV (E-02, E-03, ADR-0024).

Li scarica il processo della CLI, in un passo che non riceve il workspace: nessun dato derivato dal
repository analizzato raggiunge la rete (si scarica l'intero file e si cerca in locale). Non c'è
codice di terzi, quindi nessun container (opzione 2 di ADR-0024). Il file scaricato è non fidato:
HTTPS, redirect solo verso l'host dell'origine, tetto di byte durante la lettura, tetto sulla
decompressione, poi la lettura difensiva del nucleo (forma, numero di voci, plausibilità). Se non
supera tutto, si scarta per intero e resta lo snapshot precedente.

Cache per utente, come `feeds.py`: `<cache>/enrichment/<feed>/current.json` punta a `snap-*/data`;
il puntatore si scambia in modo atomico solo dopo la validazione. Cache e puntatore sono letti come
dati non fidati (`O_NOFOLLOW`, tetto di byte, SHA-256 del contenuto confrontato con quello del
puntatore). Una cache non posseduta dall'utente o scrivibile da altri è un errore di ambiente.

Oltre un giorno (`max_age_hours`) si risincronizza; senza rete, offline o con un fallimento si usa
lo snapshot esistente con un avviso (`feeds-stale` offline, `feeds-sync-failed` dopo un tentativo);
senza alcuno snapshot l'avviso è `enrichment-feed-missing` e le risposte sono `snapshot-absent`.
L'origine è un'etichetta nel report (`public` o `mirror`), mai un URL.
"""

import contextlib
import hashlib
import http.client
import os
import re
import shutil
import stat
import tempfile
import urllib.error
import urllib.request
import zlib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Literal, Protocol
from urllib.parse import urlsplit

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, ValidationError

from ca_core.models.scan_report import EnrichmentSnapshot, Warning_
from ca_core.ports import Clock
from ca_core.scoring.feeds.limits import FeedLimits, load_limits
from ca_core.scoring.feeds.parse import (
    EpssTable,
    FeedRejected,
    KevTable,
    parse_epss,
    parse_kev,
    plausible,
)
from ca_core.scoring.feeds.snapshot import SnapshotFeeds

PUBLIC_EPSS = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
PUBLIC_KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
POINTER = "current.json"
DATA = "data"
FEEDS = ("epss", "kev")
_SNAP = re.compile(r"^snap-[A-Za-z0-9_]{8}$")
_POINTER_MAX = 8192
TIMEOUT_SECONDS = 30
MAX_REDIRECTS = 5
USER_AGENT = "code-analyzer"


class EnrichmentError(RuntimeError):
    """Cache non utilizzabile (proprietario o permessi): errore di ambiente, non un ripiego."""


class FetchError(RuntimeError):
    """Scaricamento fallito; il messaggio è un codice, mai un contenuto."""


class Fetcher(Protocol):
    def fetch(self, url: str, *, max_bytes: int, gzip: bool, max_decompressed: int) -> bytes:
        """I byte del file (decompressi se `gzip`); `FetchError` oltre i tetti o in errore."""
        ...


@dataclass(frozen=True)
class Origin:
    """Da dove si scaricano i feed. Solo da flag o ambiente, mai da `.code-analyzer.yml`."""

    epss_url: str = PUBLIC_EPSS
    kev_url: str = PUBLIC_KEV

    @property
    def label(self) -> Literal["public", "mirror"]:
        return "public" if (self.epss_url, self.kev_url) == (PUBLIC_EPSS, PUBLIC_KEV) else "mirror"


def check_url(url: str, *, allow_loopback_http: bool = False) -> str:
    """URL ammesso: `https` con un host, senza credenziali; `http` solo su loopback se permesso."""
    parts = urlsplit(url)
    local = parts.hostname in ("127.0.0.1", "::1", "localhost")
    ok_scheme = parts.scheme == "https" or (
        parts.scheme == "http" and local and allow_loopback_http
    )
    if not ok_scheme or not parts.hostname or parts.username or parts.password or parts.fragment:
        raise ValueError("URL di origine non valido: serve https, un host e nessuna credenziale")
    return url


EPSS_URL_ENV = "CA_FEEDS_EPSS_URL"
KEV_URL_ENV = "CA_FEEDS_KEV_URL"


def origin_from_env(
    environ: dict[str, str] | None = None, *, allow_loopback_http: bool = False
) -> Origin:
    """L'origine dalle variabili d'ambiente, mai da `.code-analyzer.yml` (ADR-0014, E-04).

    Ognuna è facoltativa e sostituisce solo il proprio feed; un URL non ammesso è un errore
    (`ValueError`, senza ripetere l'URL): meglio fallire che scaricare da un altro posto.
    """
    env = os.environ if environ is None else environ
    epss = env.get(EPSS_URL_ENV) or PUBLIC_EPSS
    kev = env.get(KEV_URL_ENV) or PUBLIC_KEV
    return Origin(
        check_url(epss, allow_loopback_http=allow_loopback_http),
        check_url(kev, allow_loopback_http=allow_loopback_http),
    )


class _SameHostRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, host: str, *, allow_http: bool) -> None:
        self._host, self._allow_http, self._count = host, allow_http, 0

    def redirect_request(  # type: ignore[no-untyped-def]
        self, req, fp, code, msg, headers, newurl
    ):
        self._count += 1
        target = urlsplit(newurl)
        if self._count > MAX_REDIRECTS or target.hostname != self._host:
            raise urllib.error.URLError("redirect-refused")
        if target.scheme != "https" and not (self._allow_http and target.scheme == "http"):
            raise urllib.error.URLError("redirect-refused")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class UrllibFetcher:
    """Scarica con la libreria standard. Nessuna autenticazione, nessun cookie, nessun proxy
    configurabile dal repository; il tetto di byte vale durante la lettura."""

    def __init__(self, *, allow_loopback_http: bool = False) -> None:
        self._allow_http = allow_loopback_http

    def fetch(self, url: str, *, max_bytes: int, gzip: bool, max_decompressed: int) -> bytes:
        check_url(url, allow_loopback_http=self._allow_http)
        host = urlsplit(url).hostname or ""
        opener = urllib.request.build_opener(_SameHostRedirect(host, allow_http=self._allow_http))
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})  # noqa: S310
        try:
            with opener.open(request, timeout=TIMEOUT_SECONDS) as response:  # noqa: S310
                if response.status != 200:
                    raise FetchError("http-status")
                return _read(response, max_bytes, gzip, max_decompressed)
        except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as exc:
            raise FetchError("network") from exc


def _read(response: http.client.HTTPResponse, max_bytes: int, gzip: bool, cap: int) -> bytes:
    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS) if gzip else None
    raw = out = 0
    chunks: list[bytes] = []
    while chunk := response.read(64 * 1024):
        raw += len(chunk)
        if raw > max_bytes:
            raise FetchError("too-large")
        if decompressor is None:
            chunks.append(chunk)
            continue
        try:
            part = decompressor.decompress(chunk, cap - out + 1)
        except zlib.error as exc:
            raise FetchError("gzip") from exc
        out += len(part)
        if out > cap or decompressor.unconsumed_tail:
            raise FetchError("too-large")
        chunks.append(part)
    if decompressor is not None and not decompressor.eof:
        raise FetchError("gzip")
    return b"".join(chunks)


# --- cache ------------------------------------------------------------------------------------


class _Pointer(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    dir: str
    downloaded_at: AwareDatetime
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    origin: Literal["public", "mirror"]
    entries: int = Field(ge=0)


def default_cache_dir(environ: dict[str, str] | None = None) -> Path:
    env = os.environ if environ is None else environ
    base = env.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "code-analyzer" / "feeds" / "enrichment"


def _private_dir(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise EnrichmentError(f"cache dei feed non privata: {path.name}")


def _read_regular(path: Path, limit: int) -> bytes | None:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            return None
        data = os.read(fd, limit + 1)
        while len(data) <= limit:
            more = os.read(fd, 1 << 20)
            if not more:
                break
            data += more
    except OSError:
        return None
    finally:
        os.close(fd)
    return data if len(data) <= limit else None


def _load_pointer(feed_dir: Path) -> _Pointer | None:
    raw = _read_regular(feed_dir / POINTER, _POINTER_MAX)
    if raw is None:
        return None
    try:
        pointer = _Pointer.model_validate_json(raw)
    except ValidationError:
        return None
    return pointer if _SNAP.fullmatch(pointer.dir) else None


def _publish(feed_dir: Path, pointer: _Pointer) -> None:
    fd, tmp = tempfile.mkstemp(prefix="pointer-", dir=feed_dir)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(pointer.model_dump_json())
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, feed_dir / POINTER)  # atomico: lo scambio avviene solo qui
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _prune(feed_dir: Path, keep: set[str]) -> None:
    for entry in feed_dir.iterdir():
        if _SNAP.fullmatch(entry.name) and entry.name not in keep:
            if stat.S_ISLNK(entry.lstat().st_mode):
                with contextlib.suppress(OSError):
                    entry.unlink()  # mai seguire un link, nemmeno per purgare
            else:
                shutil.rmtree(entry, ignore_errors=True)


@dataclass
class _Loaded:
    pointer: _Pointer
    table: EpssTable | KevTable


def _parse(feed: str, raw: bytes, limits: FeedLimits) -> EpssTable | KevTable:
    return parse_epss(raw, limits.epss) if feed == "epss" else parse_kev(raw, limits.kev)


def _data_limit(feed: str, limits: FeedLimits) -> int:
    return limits.epss.max_decompressed_bytes if feed == "epss" else limits.kev.max_download_bytes


def _load_cached(feed_dir: Path, feed: str, limits: FeedLimits) -> _Loaded | None:
    """Lo snapshot in cache, riletto e riconvalidato: un file alterato o diverso dal puntatore è
    come se non ci fosse."""
    pointer = _load_pointer(feed_dir)
    if pointer is None:
        return None
    raw = _read_regular(feed_dir / pointer.dir / DATA, _data_limit(feed, limits))
    if raw is None or hashlib.sha256(raw).hexdigest() != pointer.sha256:
        return None
    try:
        return _Loaded(pointer, _parse(feed, raw, limits))
    except FeedRejected:
        return None


def _entries(table: EpssTable | KevTable) -> int:
    return len(table.entries)


def _content_date(table: EpssTable | KevTable) -> datetime:
    return table.score_date if isinstance(table, EpssTable) else table.date_released


def _check_progress(previous: EpssTable | KevTable, table: EpssTable | KevTable) -> None:
    """S5-M1 e S5-M2: uno snapshot autentico ma vecchio, o con voci di KEV tolte, non è un
    aggiornamento. Il conteggio da solo non lo vede (si possono alterare migliaia di righe senza
    cambiarlo). Il rifiuto è nel verso sicuro: resta lo snapshot precedente, con l'avviso."""
    if _content_date(table) < _content_date(previous):
        raise FeedRejected("older-than-previous")
    if isinstance(table, KevTable) and isinstance(previous, KevTable):
        if set(previous.entries) - set(table.entries):
            raise FeedRejected("kev-entry-removed")  # il catalogo di CISA cresce, non si accorcia


def _download(
    feed: str,
    feed_dir: Path,
    url: str,
    fetcher: Fetcher,
    limits: FeedLimits,
    origin: Origin,
    clock: Clock,
    previous: _Loaded | None,
) -> _Loaded:
    """Scarica, valida e pubblica; `FetchError`, `FeedRejected` o `OSError` se non riesce."""
    if feed == "epss":
        cap = limits.epss.max_download_bytes
        raw = fetcher.fetch(
            url, max_bytes=cap, gzip=True, max_decompressed=limits.epss.max_decompressed_bytes
        )
    else:
        cap = limits.kev.max_download_bytes
        raw = fetcher.fetch(url, max_bytes=cap, gzip=False, max_decompressed=cap)
    table = _parse(feed, raw, limits)
    before = _entries(previous.table) if previous else None
    if not plausible(_entries(table), before, limits.max_drop_percent):
        raise FeedRejected("implausible-drop")
    if previous is not None:
        _check_progress(previous.table, table)
    new_dir = Path(tempfile.mkdtemp(prefix="snap-", dir=feed_dir))
    published = False
    try:
        (new_dir / DATA).write_bytes(raw)
        pointer = _Pointer(
            dir=new_dir.name,
            downloaded_at=clock.now(),
            sha256=hashlib.sha256(raw).hexdigest(),
            origin=origin.label,
            entries=_entries(table),
        )
        _publish(feed_dir, pointer)
        published = True
        _prune(feed_dir, {new_dir.name})
        return _Loaded(pointer, table)
    finally:
        if not published:
            shutil.rmtree(new_dir, ignore_errors=True)


@dataclass(frozen=True)
class EnrichmentResult:
    feeds: SnapshotFeeds
    warnings: list[Warning_]


def _warning(code: str, message: str, feed: str) -> Warning_:
    return Warning_(code=code, message=message, subject=feed)


def _identity(loaded: _Loaded) -> EnrichmentSnapshot:
    return EnrichmentSnapshot(
        feed="epss" if isinstance(loaded.table, EpssTable) else "kev",
        origin=loaded.pointer.origin,
        downloaded_at=loaded.pointer.downloaded_at,
        sha256=loaded.pointer.sha256,
        content=loaded.table.identity(),
    )


def load_enrichment(
    cache_dir: Path,
    fetcher: Fetcher,
    clock: Clock,
    *,
    offline: bool = False,
    origin: Origin | None = None,
    limits: FeedLimits | None = None,
    on_sync: Callable[[str], None] | None = None,
) -> EnrichmentResult:
    """EPSS e KEV per la scansione, sincronizzando se mancano o sono vecchi."""
    origin = origin or Origin()
    limits = limits or load_limits()
    max_age = timedelta(hours=limits.max_age_hours)
    _private_dir(cache_dir)
    loaded: dict[str, _Loaded | None] = {}
    warnings: list[Warning_] = []
    for feed in FEEDS:
        feed_dir = cache_dir / feed
        _private_dir(feed_dir)
        current = _load_cached(feed_dir, feed, limits)
        now = clock.now()
        fresh = (
            current is not None and timedelta(0) <= now - current.pointer.downloaded_at <= max_age
        )
        if fresh:
            loaded[feed] = current
            continue
        if offline:
            loaded[feed] = current
            warnings.append(
                _warning("feeds-stale", "snapshot non aggiornato (offline)", feed)
                if current
                else _warning("enrichment-feed-missing", "nessuno snapshot (offline)", feed)
            )
            continue
        if on_sync is not None:
            on_sync(feed)
        url = origin.epss_url if feed == "epss" else origin.kev_url
        try:
            loaded[feed] = _download(feed, feed_dir, url, fetcher, limits, origin, clock, current)
        except FetchError, FeedRejected, OSError:
            loaded[feed] = current
            warnings.append(
                _warning("feeds-sync-failed", "sincronizzazione fallita: snapshot precedente", feed)
                if current
                else _warning(
                    "enrichment-feed-missing", "sincronizzazione fallita e nessuno snapshot", feed
                )
            )
    epss, kev = loaded["epss"], loaded["kev"]
    snapshots = [_identity(x) for x in (epss, kev) if x is not None]
    feeds = SnapshotFeeds(
        epss.table if epss and isinstance(epss.table, EpssTable) else None,
        kev.table if kev and isinstance(kev.table, KevTable) else None,
        snapshots,
    )
    return EnrichmentResult(feeds, warnings)

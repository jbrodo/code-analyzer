"""Lettura difensiva dei file EPSS e KEV (E-01, ADR-0024). Solo libreria standard, nessun I/O.

Il file scaricato è un dato non fidato: si accetta solo se supera tutti i controlli (forma, numero
di voci, valori), altrimenti `FeedRejected` con un codice, mai un pezzo del contenuto. La dimensione
scaricata e la decompressione le limita chi scarica, durante la lettura; qui si controllano i byte
già in memoria. Del testo di KEV (descrizioni, azioni richieste, note) si legge solo `cveID`,
`dateAdded` e `knownRansomwareCampaignUse`: il resto non entra mai nel report.
"""

import json
import math
import re
from dataclasses import dataclass, field
from datetime import UTC, date, datetime

from ca_core.ports import validate_cve
from ca_core.scoring.feeds.limits import EpssLimits, KevLimits

_EPSS_HEAD = re.compile(
    r"^#model_version:(?P<model>v[0-9A-Za-z.\-]{1,32}),"
    r"score_date:(?P<date>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)$"
)
_EPSS_COLUMNS = "cve,epss,percentile"
_VERSION = re.compile(r"^[0-9A-Za-z.\-]{1,64}$")
_RANSOMWARE = {"Known", "Unknown"}


class FeedRejected(ValueError):
    """Il file non è un feed valido; il messaggio è un codice stabile, mai un contenuto."""


@dataclass(frozen=True)
class EpssTable:
    model_version: str
    score_date: datetime
    entries: dict[str, tuple[float, float]] = field(default_factory=dict)  # cve -> (epss, perc.)

    def identity(self) -> dict[str, str]:
        return {
            "model_version": self.model_version,
            "score_date": self.score_date.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }


@dataclass(frozen=True)
class KevTable:
    catalog_version: str
    date_released: datetime
    entries: dict[str, tuple[date, str | None]] = field(default_factory=dict)

    def identity(self) -> dict[str, str]:
        return {
            "catalog_version": self.catalog_version,
            "date_released": self.date_released.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }


def _unit(text: str) -> float:
    try:
        value = float(text)
    except ValueError as exc:
        raise FeedRejected("epss-number") from exc
    if not math.isfinite(value) or not 0.0 <= value <= 1.0:
        raise FeedRejected("epss-range")
    return value


def parse_epss(raw: bytes, limits: EpssLimits) -> EpssTable:
    if len(raw) > limits.max_decompressed_bytes:
        raise FeedRejected("epss-too-large")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise FeedRejected("epss-encoding") from exc
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    if len(lines) < 2:
        raise FeedRejected("epss-shape")
    head = _EPSS_HEAD.fullmatch(lines[0])
    if head is None or lines[1] != _EPSS_COLUMNS:
        raise FeedRejected("epss-shape")
    try:
        score_date = datetime.strptime(head["date"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise FeedRejected("epss-shape") from exc
    entries: dict[str, tuple[float, float]] = {}
    for line in lines[2:]:
        parts = line.split(",")
        if len(parts) != 3:
            raise FeedRejected("epss-row")
        try:
            cve = validate_cve(parts[0])
        except ValueError as exc:
            raise FeedRejected("epss-cve") from exc
        if cve in entries:
            raise FeedRejected("epss-duplicate")
        entries[cve] = (_unit(parts[1]), _unit(parts[2]))
        if len(entries) > limits.max_entries:
            raise FeedRejected("epss-too-many")
    if len(entries) < limits.min_entries:
        raise FeedRejected("epss-too-few")
    return EpssTable(head["model"], score_date, entries)


def parse_kev(raw: bytes, limits: KevLimits) -> KevTable:
    if len(raw) > limits.max_download_bytes:
        raise FeedRejected("kev-too-large")
    try:
        document = json.loads(raw)
    except (ValueError, RecursionError) as exc:
        raise FeedRejected("kev-json") from exc
    if not isinstance(document, dict):
        raise FeedRejected("kev-shape")
    version, released = document.get("catalogVersion"), document.get("dateReleased")
    items = document.get("vulnerabilities")
    if not isinstance(version, str) or not _VERSION.fullmatch(version):
        raise FeedRejected("kev-version")
    if not isinstance(released, str) or not isinstance(items, list):
        raise FeedRejected("kev-shape")
    try:
        when = datetime.fromisoformat(released.replace("Z", "+00:00"))
    except ValueError as exc:
        raise FeedRejected("kev-date") from exc
    if when.tzinfo is None:
        raise FeedRejected("kev-date")
    if len(items) > limits.max_entries:
        raise FeedRejected("kev-too-many")
    entries: dict[str, tuple[date, str | None]] = {}
    for item in items:
        if not isinstance(item, dict):
            raise FeedRejected("kev-row")
        try:
            cve = validate_cve(item.get("cveID", ""))
            added = date.fromisoformat(item["dateAdded"])
        except (ValueError, KeyError, TypeError) as exc:
            raise FeedRejected("kev-row") from exc
        ransomware = item.get("knownRansomwareCampaignUse")
        if ransomware is not None and ransomware not in _RANSOMWARE:
            raise FeedRejected("kev-row")
        if cve in entries:
            raise FeedRejected("kev-duplicate")
        entries[cve] = (added, ransomware)
    if len(entries) < limits.min_entries:
        raise FeedRejected("kev-too-few")
    return KevTable(version, when, entries)


def plausible(new_count: int, previous_count: int | None, max_drop_percent: int) -> bool:
    """Un calo oltre la soglia rispetto allo snapshot precedente è sospetto (ADR-0024)."""
    if previous_count is None or previous_count == 0:
        return True
    return new_count * 100 >= previous_count * (100 - max_drop_percent)

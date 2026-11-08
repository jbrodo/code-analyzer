"""Lettura di SARIF 2.1.0 prodotto da un plugin (K-01, ADR-0003, ADR-0007).

L'input è non fidato. Ordine delle difese, dalla più economica:

1. dimensione in byte, prima di leggere (file: solo regolari, senza seguire symlink);
2. parsing JSON senza `NaN`/`Infinity`, con profondità massima;
3. numero di `runs` e di `results`, prima della validazione dello schema;
4. validazione contro lo schema SARIF fissato (`SchemaStore`, senza rete);
5. validazione delle `properties` di ogni `result` contro il contratto C-05;
6. controlli aggiuntivi opzionali (`checks`), punto di innesto del controllo strutturale K-10.

Ogni rifiuto è un `SarifError`: nessuna altra eccezione esce da qui.
"""

import json
import os
import stat
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from ca_core.formats import SARIF_VERSION
from ca_core.models.plugin_sarif import PluginSarifProperties
from ca_core.sarif.errors import SarifError, SarifErrorCode
from ca_core.schema_validation import SchemaStore

DEFAULT_MAX_BYTES = 50 * 1024 * 1024  # come l'esempio di manifest; il limite vero è `max_bytes`
MAX_REPORTED = 20
_MAX_PATH_CHARS = 200

# Controllo aggiuntivo sul documento già valido; solleva `SarifError` per rifiutarlo.
SarifCheck = Callable[[Mapping[str, Any]], None]


@dataclass(frozen=True)
class SarifLimits:
    """Limiti di lettura. `max_bytes` viene da `outputs.max_bytes` del manifest (ADR-0004).

    I valori predefiniti sono 20 volte i campioni reali più grandi (osv-scanner: 88 risultati,
    417 KB; profondità massima osservata 14) e vanno rivisti con i pilota (X-04).
    """

    max_bytes: int = DEFAULT_MAX_BYTES
    max_depth: int = 64
    max_runs: int = 16
    max_results: int = 100_000

    def __post_init__(self) -> None:
        if min(self.max_bytes, self.max_depth, self.max_runs, self.max_results) < 1:
            raise ValueError("i limiti devono essere positivi")


@dataclass(frozen=True)
class SarifResult:
    run_index: int
    index: int
    data: Mapping[str, Any]
    properties: PluginSarifProperties | None  # None se il result non ha `properties`


@dataclass(frozen=True)
class ParsedSarif:
    document: Mapping[str, Any]
    results: tuple[SarifResult, ...]


def _reject_constant(name: str) -> Any:
    raise ValueError("costante JSON non ammessa")


def _depth_exceeds(document: Any, max_depth: int) -> bool:
    """Visita iterativa: la profondità si misura senza ricorsione sul dato ostile."""
    stack: list[tuple[Any, int]] = [(document, 1)]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, dict):
            children: Any = node.values()
        elif isinstance(node, list):
            children = node
        else:
            continue
        if depth >= max_depth and children:
            return True
        stack.extend((child, depth + 1) for child in children)
    return False


def _json_path(error_path: str) -> str:
    return error_path.partition(": ")[0][:_MAX_PATH_CHARS]


def _count(document: Any, limits: SarifLimits) -> None:
    runs = document.get("runs") if isinstance(document, dict) else None
    if not isinstance(runs, list):
        return  # lo schema lo rifiuta con il suo errore
    if len(runs) > limits.max_runs:
        raise SarifError(SarifErrorCode.TOO_MANY_RUNS, f"più di {limits.max_runs} run")
    total = 0
    for run in runs:
        results = run.get("results") if isinstance(run, dict) else None
        total += len(results) if isinstance(results, list) else 0
        if total > limits.max_results:
            raise SarifError(
                SarifErrorCode.TOO_MANY_RESULTS, f"più di {limits.max_results} risultati"
            )


def _iter_results(document: Mapping[str, Any]) -> Iterator[tuple[int, int, Mapping[str, Any]]]:
    for run_index, run in enumerate(document.get("runs") or ()):
        for index, result in enumerate(run.get("results") or ()):
            yield run_index, index, result


def _parse_properties(document: Mapping[str, Any]) -> tuple[SarifResult, ...]:
    parsed: list[SarifResult] = []
    problems: list[str] = []
    for run_index, index, result in _iter_results(document):
        raw = result.get("properties")
        properties = None
        if raw is not None:
            try:
                # Strict in modalità JSON: in modalità Python `strict` rifiuta il testo per un
                # enum (`category`); il JSON resta stretto sui tipi (es. `"9"` per un numero).
                properties = PluginSarifProperties.model_validate_json(json.dumps(raw), strict=True)
            except ValidationError as exc:
                base = f"/runs/{run_index}/results/{index}/properties"
                # `loc` e non `msg`: il messaggio può citare il valore ricevuto.
                problems += [
                    f"{base}/{'/'.join(str(p) for p in e['loc'])}"[:_MAX_PATH_CHARS]
                    for e in exc.errors(include_input=False, include_url=False)
                ]
                if len(problems) >= MAX_REPORTED:
                    break
        parsed.append(SarifResult(run_index, index, result, properties))
    if problems:
        raise SarifError(
            SarifErrorCode.PROPERTIES,
            "properties non conformi al contratto delle proprietà SARIF",
            tuple(problems[:MAX_REPORTED]),
        )
    return tuple(parsed)


def parse_sarif(
    data: bytes,
    store: SchemaStore,
    limits: SarifLimits | None = None,
    checks: Sequence[SarifCheck] = (),
) -> ParsedSarif:
    """Valida `data` come SARIF 2.1.0 di un plugin; `SarifError` se non è utilizzabile."""
    limits = limits or SarifLimits()
    if len(data) > limits.max_bytes:
        raise SarifError(SarifErrorCode.TOO_LARGE, f"oltre {limits.max_bytes} byte")
    try:
        document = json.loads(data, parse_constant=_reject_constant)
    except RecursionError as exc:
        raise SarifError(SarifErrorCode.TOO_DEEP, "documento troppo annidato") from exc
    except ValueError as exc:  # JSON non valido, UTF-8 non valido, interi enormi
        raise SarifError(SarifErrorCode.NOT_JSON, "non è JSON valido") from exc
    if _depth_exceeds(document, limits.max_depth):
        raise SarifError(SarifErrorCode.TOO_DEEP, f"profondità oltre {limits.max_depth}")
    _count(document, limits)
    errors = store.validate_sarif(document)
    if errors:
        raise SarifError(
            SarifErrorCode.SCHEMA,
            f"non conforme a SARIF {SARIF_VERSION}",
            tuple(_json_path(e) for e in errors),
        )
    results = _parse_properties(document)
    for check in checks:
        check(document)
    return ParsedSarif(document, results)


def read_sarif_file(
    path: Path,
    store: SchemaStore,
    limits: SarifLimits | None = None,
    checks: Sequence[SarifCheck] = (),
) -> ParsedSarif:
    """Come `parse_sarif`, da un file regolare: i symlink non si seguono (ADR-0004)."""
    limits = limits or SarifLimits()
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    try:
        fd = os.open(path, flags)
    except (OSError, ValueError) as exc:
        raise SarifError(SarifErrorCode.UNREADABLE, "file non apribile") from exc
    try:
        with os.fdopen(fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise SarifError(SarifErrorCode.UNREADABLE, "non è un file regolare")
            if info.st_size > limits.max_bytes:
                raise SarifError(SarifErrorCode.TOO_LARGE, f"oltre {limits.max_bytes} byte")
            data = handle.read(limits.max_bytes + 1)  # il file può crescere dopo fstat
    except OSError as exc:
        raise SarifError(SarifErrorCode.UNREADABLE, "lettura fallita") from exc
    return parse_sarif(data, store, limits, checks)

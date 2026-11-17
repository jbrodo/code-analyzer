"""Punteggi in ombra e contesto di una scansione (K-03, K-04, K-05, K-14, ADR-0021, ADR-0028).

La radice di composizione sceglie da dove viene ogni dato; il nucleo non fa I/O. Un file di
configurazione di scoring e un file di contesto del servizio vengono **da fuori dal repository
analizzato** (come la baseline, ADR-0025): un percorso dentro la directory analizzata è rifiutato,
perché una PR potrebbe contenerlo e abbassare i propri punteggi. Mai da `.code-analyzer.yml`
(ADR-0014), da cui si legge solo la scelta della variante e il blocco `service` (non verificato).
"""

import argparse
import os
from dataclasses import dataclass
from pathlib import Path

from pydantic import ValidationError

from ca_cli.composition import Context
from ca_cli.scan import ScanError
from ca_core.models.config import CodeAnalyzerConfig
from ca_core.models.finding import Finding
from ca_core.models.graph import Graph
from ca_core.models.scan_report import EnrichmentSnapshot, ScoringInfo, ServiceContext, Warning_
from ca_core.models.service_context_file import ServiceContextFile
from ca_core.ports import SourceError
from ca_core.scoring.base import ScoringContext
from ca_core.scoring.churn import ChurnIndex
from ca_core.scoring.config import ScoringConfigError, config_version, resolve_config
from ca_core.scoring.reach import NoReachability, Reachability
from ca_core.scoring.score import Variant, score_findings
from ca_core.scoring.service import resolve_service_context
from ca_graph.reachability import GraphReachability
from ca_plugins.enrichment import FetchError, load_enrichment, origin_from_env
from ca_plugins.feeds import default_cache_dir as default_feeds_dir

SCORING_CONFIG_ENV = "CA_SCORING_CONFIG"
MAX_INPUT_BYTES = 256 * 1024


@dataclass(frozen=True)
class ScoringOutcome:
    findings: list[Finding]
    info: ScoringInfo
    service: ServiceContext
    enrichment: list[EnrichmentSnapshot]
    warnings: list[Warning_]


def _read_outside(path: str, label: str, workspace: str, context: Context) -> bytes:
    """Il file, letto con tetto di byte; fuori dalla directory analizzata, dopo `realpath`."""
    resolved = Path(os.path.realpath(path))
    root = Path(os.path.realpath(workspace))
    if resolved == root or root in resolved.parents:
        raise ScanError(f"{label}: il file sta dentro la directory analizzata")
    try:
        return context.source.read_file(str(resolved.parent), resolved.name, MAX_INPUT_BYTES)
    except SourceError as exc:
        raise ScanError(f"{label}: file non leggibile o troppo grande") from exc


def _scoring_bytes(args: argparse.Namespace, workspace: str, context: Context) -> bytes | None:
    path = getattr(args, "scoring_config", None) or os.environ.get(SCORING_CONFIG_ENV)
    return _read_outside(path, "configurazione di scoring", workspace, context) if path else None


def _service_file(
    args: argparse.Namespace, workspace: str, context: Context
) -> ServiceContextFile | None:
    path = getattr(args, "service_context", None)
    if not path:
        return None
    raw = _read_outside(path, "contesto del servizio", workspace, context)
    try:
        return ServiceContextFile.model_validate_json(raw)
    except ValidationError as exc:
        raise ScanError(f"contesto del servizio non valido ({exc.error_count()} errori)") from exc


def _variant(args: argparse.Namespace, config: CodeAnalyzerConfig, default: str) -> Variant:
    """`--variant`, poi `scoring.variant` della configurazione effettiva, poi il file di scoring."""
    chosen = getattr(args, "variant", None)
    if chosen is None and config.scoring is not None:
        chosen = config.scoring.variant
    value = chosen or default
    if value not in ("A", "B"):
        raise ScanError("variante non valida")
    return value  # type: ignore[return-value]


def run_scoring(
    args: argparse.Namespace,
    context: Context,
    *,
    config: CodeAnalyzerConfig,
    workspace: str,
    findings: list[Finding],
    graph: Graph | None,
) -> ScoringOutcome:
    warnings: list[Warning_] = []
    try:
        scoring = resolve_config(flag=_scoring_bytes(args, workspace, context))
    except ScoringConfigError as exc:
        raise ScanError(str(exc)) from exc
    service, service_warnings = resolve_service_context(
        _service_file(args, workspace, context), config.service
    )
    warnings += service_warnings
    feeds_dir = (context.feeds_cache or default_feeds_dir()) / "enrichment"
    try:
        origin = origin_from_env()
    except ValueError as exc:
        raise ScanError("origine dei feed non valida") from exc
    enriched = load_enrichment(
        feeds_dir,
        context.enrichment_fetcher or _NoNetwork(),
        context.clock,
        offline=args.offline or context.enrichment_fetcher is None,
        origin=origin,
        limits=context.enrichment_limits,
    )
    warnings += enriched.warnings
    reach: Reachability = GraphReachability(graph) if graph is not None else NoReachability()
    churn = ChurnIndex(graph) if graph is not None else None
    result = score_findings(
        findings,
        ScoringContext(
            config=scoring, service=service, reachability=reach, feeds=enriched.feeds, churn=churn
        ),
        active_variant=_variant(args, config, scoring.variant),
        config_version=config_version(scoring),
    )
    if result.with_fallback:
        warnings.append(
            Warning_(
                code="scoring-with-fallbacks",
                message=f"{result.with_fallback} finding con valori di ripiego: dati mancanti",
            )
        )
    return ScoringOutcome(
        result.findings, result.info, service, enriched.feeds.snapshots(), warnings
    )


class _NoNetwork:
    """Senza un trasporto collegato (i test, `build_context` esterno) non si scarica nulla."""

    def fetch(self, url: str, *, max_bytes: int, gzip: bool, max_decompressed: int) -> bytes:
        raise FetchError("no-network")

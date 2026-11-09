"""Passo `publish` su file (K-18, ADR-0002, ADR-0010, ADR-0011): report JSON e SARIF aggregato.

Scrive solo tramite `ArtifactSink`. Ordine: prima si producono e si validano entrambi i documenti
(report contro lo schema `scan-report` generato dal modello, identico a `schemas/` per
`schema_export --check`; SARIF contro 2.1.0), poi si scrive; un documento non valido non lascia
artefatti parziali. Output deterministico: chiavi ordinate, nessun dato dell'orologio.
Commenti PR, check run, DB e ticket sono di Fase 2 (§5, passo 10).
"""

import json
from functools import lru_cache
from typing import Any

from pydantic import BaseModel, ConfigDict

from ca_core.models.scan_report import ScanReport
from ca_core.ports import ArtifactRef, ArtifactSink
from ca_core.sarif import aggregate_sarif
from ca_core.schema_export import CONTRACTS
from ca_core.schema_validation import SchemaStore

REPORT_NAME = "code-analyzer.report.json"  # nome pubblico (ADR-0010), solo qui
SARIF_NAME = "code-analyzer.sarif"


class PublishError(ValueError):
    """Il report non è conforme allo schema `scan-report`: nulla è stato scritto."""


class PublishResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    report: ArtifactRef
    sarif: ArtifactRef


@lru_cache(maxsize=1)
def _report_schema() -> dict[str, Any]:
    (contract,) = (c for c in CONTRACTS if c.name == "scan-report")
    schema: dict[str, Any] = json.loads(contract.render())
    return schema


def publish(report: ScanReport, sink: ArtifactSink, store: SchemaStore) -> PublishResult:
    document = report.model_dump(mode="json")
    errors = store.validate_with(_report_schema(), document)
    if errors:
        raise PublishError(f"report non conforme a scan-report: {errors[0]}")
    sarif = aggregate_sarif(report, store)  # SarifError se non valida
    content = json.dumps(document, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
    return PublishResult(
        report=sink.write(REPORT_NAME, content.encode()), sarif=sink.write(SARIF_NAME, sarif)
    )

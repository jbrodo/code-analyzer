"""Passo `normalize` (K-17, ADR-0002, ADR-0007, ADR-0008, ADR-0009, ADR-0012, ADR-0013, ADR-0014).

IPOTESI D-0009-A: il passo compone `level` provvisori e la policy licenze, ma non
contiene né soglie né elenchi di licenze (vengono da `scoring.levels` e dalla configurazione).

Dagli output dei plugin all'elenco ordinato dei finding. Ordine di composizione:

1. per ogni plugin riuscito, nell'ordine di `executions`: lettura confinata di SARIF e CycloneDX
   da `output_dir` con il limite `outputs.max_bytes`; `parse_sarif` con i controlli strutturali di
   K-10 (`structural_checks`) prima della normalizzazione; `normalize_sarif`; licenze dichiarate
   dall'SBOM. Un output non utilizzabile fa fallire il plugin (`failed`, finding `health`) e
   scarta tutto ciò che ne era stato letto, SARIF e SBOM insieme. Le notifiche in `invocations`
   del SARIF diventano avvisi `plugin-<id>` (K-19);
2. esclusioni `paths.exclude` (ADR-0014) su tutti i finding;
3. i finding `license` dei plugin non vanno nel report: alimentano la policy (K-12), insieme alle
   licenze dichiarate; restano i soli finding della policy;
4. deduplicazione (K-07) dei restanti; si aggiungono i finding della policy;
5. eccezioni (K-09), livelli provvisori (K-11), ordinamento.

Funzione pura rispetto alle porte: stessi ingressi e stesso `Clock`, stesso risultato.
`secret_sha256` serve solo al fingerprint e non entra nel report (lo garantisce `normalize_sarif`).
"""

from pydantic import BaseModel, ConfigDict, Field

from ca_core.correlation import assign_correlation
from ca_core.dedup import deduplicate
from ca_core.models.config import CodeAnalyzerConfig
from ca_core.models.finding import Category, Finding
from ca_core.models.scan_report import AppliedException, Outcome, PluginRun, ReportStatus, Warning_
from ca_core.normalize import (
    DeclaredLicense,
    declared_licenses,
    health_finding,
    normalize_sarif,
    notification_warnings,
)
from ca_core.pipeline.exceptions import apply_exceptions
from ca_core.pipeline.exclusions import (
    apply_exclusions,
    component_excluded,
    effective_exclusions,
)
from ca_core.pipeline.run_plugins import PluginExecution, output_name
from ca_core.policy.licenses import evaluate_licenses
from ca_core.ports import Clock, SourceError, SourceReader
from ca_core.sarif import SarifError, SarifLimits, parse_sarif, structural_checks
from ca_core.sbom import SbomError, parse_cyclonedx
from ca_core.schema_validation import SchemaStore
from ca_core.scoring.levels import assign_levels, sort_findings


class _Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class NormalizeRequest(_Frozen):
    repository: str
    commit: str | None = None
    workspace: str  # radice letta per il contesto dei finding `code`
    executions: list[PluginExecution]
    config: CodeAnalyzerConfig
    # Finding prodotti da un passo che non è un plugin SARIF, per esempio gli smell del grafo
    # (G-10). Vanno nelle stesse esclusioni, eccezioni, livelli e ordinamento degli altri.
    extra_findings: list[Finding] = Field(default_factory=list)


class NormalizeResult(_Frozen):
    findings: list[Finding]  # ordinati: livello, categoria, fingerprint
    plugins: list[PluginRun]  # per nome, con gli esiti aggiornati da questo passo
    status: ReportStatus
    exceptions: list[AppliedException]
    warnings: list[Warning_]
    exclusions: list[str]  # glob effettivi per il report


def _consume(
    execution: PluginExecution,
    request: NormalizeRequest,
    reader: SourceReader,
    store: SchemaStore,
    clock: Clock,
) -> tuple[list[Finding], list[DeclaredLicense], list[Warning_]]:
    """Findings, licenze dichiarate e notifiche di un plugin; `ValueError` se inutilizzabile."""
    manifest, directory = execution.manifest, execution.output_dir
    if directory is None:
        raise ValueError("output assente")
    outputs = manifest.outputs
    findings: list[Finding] = []
    declared: list[DeclaredLicense] = []
    notes: list[Warning_] = []
    try:
        if outputs.sarif is not None:
            data = reader.read_file(directory, output_name(outputs.sarif), outputs.max_bytes)
            parsed = parse_sarif(
                data,
                store,
                SarifLimits(max_bytes=outputs.max_bytes),
                structural_checks(manifest.name),
            )
            findings = normalize_sarif(
                parsed,
                manifest=manifest,
                repository=request.repository,
                commit=request.commit,
                workspace=request.workspace,
                reader=reader,
                clock=clock,
            )
            notes = notification_warnings(parsed, manifest.name)
        if outputs.cyclonedx is not None:
            data = reader.read_file(directory, output_name(outputs.cyclonedx), outputs.max_bytes)
            sbom = parse_cyclonedx(data, store, outputs.cyclonedx_version or "", outputs.max_bytes)
            declared = declared_licenses(sbom.document)
    except (SarifError, SbomError) as exc:
        raise ValueError(f"output non utilizzabile: {exc.code.value}") from exc
    except SourceError as exc:
        raise ValueError("output non leggibile o troppo grande") from exc
    return findings, declared, notes


def normalize(
    request: NormalizeRequest,
    reader: SourceReader,
    store: SchemaStore,
    clock: Clock,
) -> NormalizeResult:
    config = request.config
    plugins: list[PluginRun] = []
    findings: list[Finding] = list(request.extra_findings)
    declared: list[DeclaredLicense] = []
    notes: list[Warning_] = []
    for execution in sorted(request.executions, key=lambda e: e.run.name):
        run = execution.run
        if run.outcome is Outcome.OK:
            try:
                got, licenses, noted = _consume(execution, request, reader, store, clock)
            except ValueError as exc:
                run = run.model_copy(update={"outcome": Outcome.FAILED, "failure": str(exc)})
            else:
                findings += got
                notes += noted
                declared += [
                    d for d in licenses if not component_excluded(d.locations, config.paths.exclude)
                ]
        plugins.append(run)
        if run.outcome is Outcome.FAILED:
            findings.append(
                health_finding(
                    run.name,
                    run.failure or "",
                    repository=request.repository,
                    commit=request.commit,
                    clock=clock,
                )
            )

    kept = apply_exclusions(findings, config.paths.exclude)
    detected = [f for f in kept if f.category is Category.LICENSE]
    rest = deduplicate([f for f in kept if f.category is not Category.LICENSE])
    policy = evaluate_licenses(
        declared=declared,
        detected=detected,
        licenses=config.licenses,
        repository=request.repository,
        commit=request.commit,
        clock=clock,
    )
    excepted = apply_exceptions([*rest, *policy.findings], config.exceptions, clock)
    failed = any(p.outcome is Outcome.FAILED for p in plugins)
    return NormalizeResult(
        findings=sort_findings(assign_levels(assign_correlation(excepted.findings))),
        plugins=plugins,
        status=ReportStatus.PARTIAL if failed else ReportStatus.COMPLETE,
        exceptions=excepted.applied,
        warnings=[*notes, *policy.warnings, *excepted.warnings],
        exclusions=effective_exclusions(config.paths.exclude),
    )

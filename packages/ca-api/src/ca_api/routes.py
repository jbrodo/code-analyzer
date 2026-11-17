"""Route dell'API v1 dichiarate dal contratto (C-08, ADR-0017, ADR-0019, ADR-0029).

Il contratto precede il codice: ogni route ha modelli di richiesta e risposta, errori ed esempi, e
`operationId` esplicito e stabile. Qui nessuna route è ancora realizzata: rispondono 501 `not-
implemented` con il formato di errore unico. Le realizzano B-03 (ingestione), B-04 e B-05
(autenticazione e ruoli), B-06, B-08..B-11. `x-required-roles` è la riga della matrice di ADR-0019
(`P`: identità di una pipeline), che B-05 verifica con i test.
"""

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Body, File, Path, Query, Request, Response, UploadFile
from fastapi.concurrency import run_in_threadpool

from ca_api.auth.authorize import (
    Admin,
    Pipeline,
    Reader,
    ReaderOrPipeline,
    User,
    authorize_patch,
)
from ca_api.auth.deps import CurrentIdentity
from ca_api.ingest import Parts, ingest
from ca_api.models import (
    FindingDetail,
    FindingPage,
    FindingPatch,
    Me,
    RepositoryPage,
    RepositoryPatch,
    RepositorySummary,
    ScanDetail,
    ScanPage,
    ScanRef,
    SortKey,
)
from ca_api.problem import PROBLEM_MEDIA_TYPE, ApiProblem, Problem, ProblemCode
from ca_core.models.finding import Category, Level, Status
from ca_core.models.graph import Graph
from ca_core.models.service_context_file import ServiceContextFile
from ca_core.schema_validation import SchemaStore

LIMIT_MAX = 200
ID = Annotated[UUID, Path(description="Identificativo opaco.")]


def _problem(description: str) -> dict[str, Any]:
    return {"model": Problem, "description": description, "content": {PROBLEM_MEDIA_TYPE: {}}}


COMMON: dict[int | str, dict[str, Any]] = {
    401: _problem("Token mancante o non valido."),
    403: _problem("Azione non permessa dal ruolo o dall'identità."),
    404: _problem("Risorsa inesistente, o di un altro tenant (l'esistenza non si rivela)."),
    422: _problem("Richiesta non valida."),
    500: _problem("Errore interno, senza traccia né messaggio interno."),
}


def _not_implemented() -> None:
    raise ApiProblem(501, ProblemCode.NOT_IMPLEMENTED)


def roles(value: str) -> dict[str, Any]:
    return {"x-required-roles": value}


router = APIRouter(prefix="/v1", responses=COMMON)
READ = "lettore, triage, approvatore, amministratore"


@router.get(
    "/me",
    operation_id="getMe",
    response_model=Me,
    summary="Identità, ruoli e tenant",
    openapi_extra=roles("utente con qualunque ruolo, o senza ruoli"),
)
def get_me(identity: User) -> Me:
    """L'unico endpoint che risponde 200 a un utente autenticato senza ruoli."""
    return Me(
        issuer=identity.issuer,
        subject=identity.subject,
        name=identity.name,
        email=identity.email,
        tenant=identity.tenant,
        roles=sorted(identity.roles),
    )


@router.get(
    "/repositories",
    operation_id="listRepositories",
    response_model=RepositoryPage,
    summary="Repository del tenant",
    openapi_extra=roles(READ),
)
def list_repositories(
    identity: Reader,
    limit: Annotated[int, Query(ge=1, le=LIMIT_MAX)] = 50,
    cursor: Annotated[str | None, Query(max_length=512)] = None,
) -> RepositoryPage:
    _not_implemented()
    raise AssertionError


@router.get(
    "/repositories/{id}",
    operation_id="getRepository",
    response_model=RepositorySummary,
    summary="Un repository, con tier ed esposizione se registrati",
    openapi_extra=roles(READ),
)
def get_repository(identity: Reader, id: ID) -> RepositorySummary:
    _not_implemented()
    raise AssertionError


@router.patch(
    "/repositories/{id}",
    operation_id="patchRepository",
    response_model=RepositorySummary,
    summary="Registra tier ed esposizione (ADR-0028)",
    openapi_extra=roles("amministratore"),
)
def patch_repository(
    identity: Admin, id: ID, body: Annotated[RepositoryPatch, Body()]
) -> RepositorySummary:
    _not_implemented()
    raise AssertionError


@router.get(
    "/repositories/{id}/scans",
    operation_id="listRepositoryScans",
    response_model=ScanPage,
    summary="Scansioni di un repository, dalla più recente",
    openapi_extra=roles(READ),
)
def list_repository_scans(
    identity: Reader,
    id: ID,
    limit: Annotated[int, Query(ge=1, le=LIMIT_MAX)] = 50,
    cursor: Annotated[str | None, Query(max_length=512)] = None,
) -> ScanPage:
    _not_implemented()
    raise AssertionError


@router.post(
    "/scans",
    operation_id="createScan",
    response_model=ScanRef,
    status_code=201,
    summary="Registra una scansione già eseguita (ingestione)",
    description=(
        "Corpo `multipart/form-data`: `report` (obbligatoria, `scan-report`), `sarif`, `sbom` e "
        "`graph` (facoltative). Ogni parte è un input non fidato, validato contro `schemas/`; un "
        "artefatto non valido respinge tutta la richiesta. Idempotente per (repository, SHA-256 "
        "del report): 201 la prima volta, 200 con lo stesso `id` alla ripetizione, 409 se la "
        "ripetizione porta artefatti diversi. Il repository del report deve coincidere con quello "
        "del token (403 `repository-mismatch`); oltre i limiti di dimensione 413."
    ),
    responses={
        200: {"model": ScanRef, "description": "Già registrata: stesso `id`, nessun effetto."},
        409: _problem("Stesso report con `sarif`, `sbom` o `graph` diversi."),
        413: _problem("Una parte o la richiesta supera i limiti di dimensione."),
    },
    openapi_extra=roles("P: solo il proprio repository"),
)
async def create_scan(
    request: Request,
    response: Response,
    identity: Pipeline,
    report: Annotated[UploadFile, File(description="`scan-report`")],
    sarif: UploadFile | None = None,
    sbom: UploadFile | None = None,
    graph: UploadFile | None = None,
) -> ScanRef:
    state = request.app.state
    if state.engine is None or state.store is None:
        raise ApiProblem(
            500, ProblemCode.INTERNAL_ERROR, detail="database o archivio non configurati"
        )
    limit = state.settings.max_part_bytes

    async def read(part: UploadFile | None) -> bytes | None:
        if part is None:
            return None
        data = await part.read(limit + 1)
        if len(data) > limit:  # il corpo intero è già limitato dal middleware, mentre si legge
            raise ApiProblem(413, ProblemCode.PAYLOAD_TOO_LARGE)
        return data

    parts = Parts(
        report=await read(report) or b"",
        sarif=await read(sarif),
        sbom=await read(sbom),
        graph=await read(graph),
    )
    schemas = state.schemas or _schemas(state)
    result = await run_in_threadpool(
        ingest,
        state.engine,
        state.store,
        schemas,
        state.settings,
        identity,
        parts,
        now=state.clock.now(),
    )
    response.status_code = 201 if result.created else 200
    return ScanRef(id=result.id)


def _schemas(state: Any) -> SchemaStore:
    state.schemas = SchemaStore.packaged()
    return state.schemas  # type: ignore[no-any-return]


@router.get(
    "/scans/{id}",
    operation_id="getScan",
    response_model=ScanDetail,
    summary="Stato e riepilogo di una scansione",
    openapi_extra=roles(f"{READ}; P: solo il proprio repository"),
)
def get_scan(identity: ReaderOrPipeline, id: ID) -> ScanDetail:
    _not_implemented()
    raise AssertionError


@router.get(
    "/scans/{id}/sarif",
    operation_id="getScanSarif",
    summary="SARIF aggregato della scansione",
    response_model=dict[str, Any],
    responses={
        200: {"description": "SARIF 2.1.0 (`ADR-0011`).", "content": {"application/sarif+json": {}}}
    },
    openapi_extra=roles(f"{READ}; P: solo il proprio repository"),
)
def get_scan_sarif(identity: ReaderOrPipeline, id: ID) -> dict[str, Any]:
    _not_implemented()
    raise AssertionError


@router.get(
    "/repositories/{id}/findings",
    operation_id="listFindings",
    response_model=FindingPage,
    summary="Finding di un repository",
    description=(
        "Senza `scan`: la scansione corrente (ADR-0018). Con `scan`: quella data, che è il modo di "
        "vedere una PR. Nessun filtro implicito sul server. Ordine totale e stabile; paginazione a "
        "cursore, che vale solo per la stessa combinazione di filtri e ordinamento."
    ),
    openapi_extra=roles(READ),
)
def list_findings(
    identity: Reader,
    id: ID,
    scan: Annotated[UUID | None, Query()] = None,
    level: Annotated[list[Level] | None, Query()] = None,
    category: Annotated[list[Category] | None, Query()] = None,
    status: Annotated[list[Status] | None, Query()] = None,
    tool: Annotated[list[str] | None, Query(max_length=50)] = None,
    new: Annotated[bool | None, Query()] = None,
    q: Annotated[
        str | None,
        Query(
            min_length=2, max_length=200, description="Sottostringa, senza espressioni regolari."
        ),
    ] = None,
    sort: SortKey = SortKey.IMPACT,
    limit: Annotated[int, Query(ge=1, le=LIMIT_MAX)] = 50,
    cursor: Annotated[str | None, Query(max_length=512)] = None,
) -> FindingPage:
    _not_implemented()
    raise AssertionError


@router.get(
    "/findings/{id}",
    operation_id="getFinding",
    response_model=FindingDetail,
    summary="Dettaglio di un finding",
    openapi_extra=roles(READ),
)
def get_finding(identity: Reader, id: ID) -> FindingDetail:
    _not_implemented()
    raise AssertionError


@router.patch(
    "/findings/{id}",
    operation_id="patchFinding",
    response_model=FindingDetail,
    summary="Triage di un finding",
    description=(
        "Un corpo cambia una cosa sola. `falso_positivo` richiede una motivazione; `accettato` si "
        "ottiene solo creando un'eccezione, con motivazione e scadenza futura; `risolto` non è "
        "assegnabile. `approved_by` è l'identità autenticata. Ruoli: `triage` per stato `aperto` o "
        "`in_corso` e owner; `approvatore` per falso positivo ed eccezioni."
    ),
    responses={409: _problem("Lo stato attuale non permette la modifica.")},
    openapi_extra=roles("triage (stato, owner); approvatore (falso positivo, eccezioni)"),
)
def patch_finding(
    identity: CurrentIdentity, id: ID, body: Annotated[FindingPatch, Body()]
) -> FindingDetail:
    authorize_patch(identity, body)
    _not_implemented()
    raise AssertionError


@router.get(
    "/repositories/{id}/sbom",
    operation_id="getRepositorySbom",
    summary="SBOM CycloneDX della scansione corrente",
    response_model=dict[str, Any],
    responses={
        200: {"description": "CycloneDX 1.7.", "content": {"application/vnd.cyclonedx+json": {}}}
    },
    openapi_extra=roles(READ),
)
def get_repository_sbom(identity: Reader, id: ID) -> dict[str, Any]:
    _not_implemented()
    raise AssertionError


@router.get(
    "/repositories/{id}/graph",
    operation_id="getRepositoryGraph",
    response_model=Graph,
    summary="Grafo dei moduli della scansione corrente",
    openapi_extra=roles(READ),
)
def get_repository_graph(identity: Reader, id: ID) -> Graph:
    _not_implemented()
    raise AssertionError


@router.get(
    "/service-context",
    operation_id="getServiceContext",
    response_model=ServiceContextFile,
    summary="Contesto del servizio del repository del token (ADR-0028)",
    openapi_extra=roles("P: solo il proprio repository"),
)
def get_service_context(identity: Pipeline) -> ServiceContextFile:
    _not_implemented()
    raise AssertionError

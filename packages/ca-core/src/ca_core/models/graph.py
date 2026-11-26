"""Contratto `graph` (C-02, ADR-0020, ADR-0022). Solo dati.

È il file che il container di estrazione di `ca-graph` scrive in `/out` e che l'host legge: un
input non fidato, come ogni uscita di plugin. È anche l'artefatto che la CLI pubblica e che il
server riceve (ADR-0018), dopo che l'host ha aggiunto le metriche: per questo `metrics` e
`packages` sono facoltativi, assenti nell'uscita del container.

Invarianti che lo schema non esprime, controllate dal modello: percorsi unici, archi ed entrypoint
che citano solo nodi presenti, elenchi ordinati (lo stesso workspace dà lo stesso file).
"""

import re
from enum import StrEnum
from typing import Annotated, Any, Literal, Self

from pydantic import (
    AfterValidator,
    AwareDatetime,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    StrictBool,
    StrictFloat,
    StrictInt,
    model_validator,
)

from ca_core.models.config import _NOT_RELATIVE, RelativePath

# Tetti del contratto: oltre, il documento è rifiutato per intero, mai troncato (ADR-0020).
MAX_MODULES = 200_000
MAX_EXTERNALS = 50_000
MAX_EDGES = 2_000_000
MAX_ENTRYPOINTS = 10_000
MAX_PATH_LENGTH = 4096
MAX_NAME_LENGTH = 214  # il limite dei nomi npm, il più largo dei due ecosistemi
MAX_COUNT = 10_000_000

# Nome di un pacchetto esterno così come compare nell'import: primo segmento per Python,
# nome con lo scope per npm. Nessuno spazio, nessun separatore di percorso oltre allo scope.
EXTERNAL_NAME_PATTERN = r"^(?:@[A-Za-z0-9._~-]+/)?[A-Za-z0-9_][A-Za-z0-9._~-]*$"

# S-02: i percorsi arrivano in UI, commenti e log. Un a capo o un NUL in un nome di file
# permetterebbe di iniettare righe (comandi del provider CI, Markdown): si rifiutano alla fonte.
_CONTROL = r"[\x00-\x1f\x7f]"


def _no_control(value: str) -> str:
    if re.search(_CONTROL, value):
        raise ValueError("carattere di controllo nel percorso")
    return value


ModulePath = Annotated[
    RelativePath,
    Field(
        max_length=MAX_PATH_LENGTH,
        json_schema_extra={"not": {"anyOf": [{"pattern": _NOT_RELATIVE}, {"pattern": _CONTROL}]}},
    ),
    AfterValidator(_no_control),
]
Count = Annotated[StrictInt, Field(ge=0, le=MAX_COUNT)]
Unit = Annotated[StrictFloat, Field(ge=0.0, le=1.0)]


class Language(StrEnum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    TSX = "tsx"


class Ecosystem(StrEnum):
    PYPI = "pypi"
    NPM = "npm"


class Confidence(StrEnum):
    """§4.3. `osservato` (dati di esecuzione) non è prodotto in Fase 2."""

    DECLARED = "dichiarato"
    INFERRED = "dedotto"
    OBSERVED = "osservato"


class ParseStatus(StrEnum):
    COMPLETE = "completa"
    PARTIAL = "parziale"  # errori di sintassi: import letti dove possibile (V-07)


class HistoryStatus(StrEnum):
    """ADR-0022: con `superficiale` e `assente` il churn è ignoto, mai un conteggio inventato."""

    COMPLETE = "completa"
    SHALLOW = "superficiale"
    ABSENT = "assente"


class EntrypointKind(StrEnum):
    PACKAGE_METADATA = "package-metadata"  # pyproject, setup.cfg, package.json
    MAIN_MODULE = "main-module"  # __main__.py, blocco `if __name__ == "__main__"`
    WEB_APPLICATION = "web-application"
    HTML_ENTRY = "html-entry"
    CONVENTION = "convention"  # manage.py, src/main.*, src/index.*


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Metrics(_Strict):
    """Calcolate dall'host sul grafo (G-04, G-08). Solo archi interni al repository."""

    fan_in: Count
    fan_out: Count
    instability: Unit
    pagerank: Unit | None = None
    # Architectural Debt Index (G-13, ADR-0023): somma dei G di B degli smell che includono il
    # modulo; per un pacchetto, la somma sui suoi moduli. Assente se B non è configurata.
    adi: Annotated[StrictFloat, Field(ge=0)] | None = None


class Module(_Strict):
    path: ModulePath
    language: Language
    parse: ParseStatus
    test: StrictBool = False
    # Commit che toccano il file nella finestra; None se la storia non la copre (ADR-0022).
    churn: Count | None = None
    # Righe fisiche del file (ADR-0023, densità di violazioni); None se il file non è leggibile.
    lines: Count | None = None
    metrics: Metrics | None = None


class External(_Strict):
    name: str = Field(pattern=EXTERNAL_NAME_PATTERN, max_length=MAX_NAME_LENGTH)
    ecosystem: Ecosystem


class Edge(_Strict):
    """Da un modulo a un modulo (`target` è un percorso) o a un pacchetto esterno (un nome)."""

    source: ModulePath
    target: str = Field(min_length=1, max_length=MAX_PATH_LENGTH)
    external: StrictBool = False
    imports: StrictInt = Field(ge=1, le=MAX_COUNT, description="Import che sostengono l'arco.")
    dynamic: StrictBool = False  # `import()` o `require` con stringa letterale fuori dalla testa
    type_only: StrictBool = False  # `import type`, blocco `TYPE_CHECKING`
    confidence: Confidence


class Entrypoint(_Strict):
    path: ModulePath
    kind: EntrypointKind
    confidence: Confidence


class Package(_Strict):
    """Una cartella con almeno un modulo (ADR-0020). Derivato dall'host."""

    path: ModulePath  # `.` per la radice del workspace
    modules: StrictInt = Field(ge=1, le=MAX_MODULES)
    metrics: Metrics


class Unresolved(_Strict):
    """Import che non hanno prodotto archi, per motivo: contati, mai inventati."""

    computed: Count = 0  # argomento non letterale
    missing: Count = 0  # relativo o alias verso un file che non c'è
    outside_workspace: Count = 0  # alias che porta fuori dal workspace
    config_extends: Count = 0  # `extends` di tsconfig non seguito
    entrypoint_missing: Count = 0  # entrypoint dichiarato verso un file assente


class Stats(_Strict):
    files_parsed: Count
    files_partial: Count = 0
    files_skipped_size: Count = 0
    files_skipped_name: Count = 0  # nomi di file con caratteri di controllo (S-02)
    unresolved: Unresolved = Field(default_factory=Unresolved)


class History(_Strict):
    status: HistoryStatus
    window_days: StrictInt = Field(ge=1, le=3650)
    head_time: AwareDatetime | None = None  # data del commit analizzato: fine della finestra
    commits_read: Count = 0


def _not_bool(value: object) -> object:
    if isinstance(value, bool):
        raise ValueError("deve essere l'intero 1")
    return value


class Graph(_Strict):
    version: Annotated[Literal[1], BeforeValidator(_not_bool)]
    modules: list[Module] = Field(default_factory=list, max_length=MAX_MODULES)
    externals: list[External] = Field(default_factory=list, max_length=MAX_EXTERNALS)
    edges: list[Edge] = Field(default_factory=list, max_length=MAX_EDGES)
    entrypoints: list[Entrypoint] = Field(default_factory=list, max_length=MAX_ENTRYPOINTS)
    packages: list[Package] = Field(default_factory=list, max_length=MAX_MODULES)
    stats: Stats
    history: History

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        paths = [m.path for m in self.modules]
        externals = [(e.ecosystem.value, e.name) for e in self.externals]
        edges = [(e.source, e.external, e.target) for e in self.edges]
        entrypoints = [(e.path, e.kind.value) for e in self.entrypoints]
        packages = [p.path for p in self.packages]
        groups: tuple[tuple[str, list[Any]], ...] = (
            ("modules", paths),
            ("externals", externals),
            ("edges", edges),
            ("entrypoints", entrypoints),
            ("packages", packages),
        )
        for name, keys in groups:
            if keys != sorted(set(keys)):
                raise ValueError(f"{name}: elenco non ordinato o con duplicati")
        known, names = set(paths), {e.name for e in self.externals}
        for edge in self.edges:
            if edge.source not in known:
                raise ValueError("arco da un modulo assente")
            if edge.target not in (names if edge.external else known):
                raise ValueError("arco verso un nodo assente")
            if not edge.external and edge.source == edge.target:
                raise ValueError("arco da un modulo a se stesso")
        if any(e.path not in known for e in self.entrypoints):
            raise ValueError("entrypoint su un modulo assente")
        if self.history.status is not HistoryStatus.COMPLETE and any(
            m.churn is not None for m in self.modules
        ):
            raise ValueError("churn valorizzato senza una storia completa")
        return self

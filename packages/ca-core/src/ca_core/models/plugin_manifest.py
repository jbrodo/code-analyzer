"""Contratto `plugin-manifest` (§7.1 rivisto da ADR-0004, 0005, 0006, 0007). Solo dati.

Due forme dello stesso contratto (ADR-0005):

- manifest sorgente: nel repository, `image` con tag e digest facoltativo;
- manifest impacchettato: nella CLI, `image` con tag e `@sha256:` obbligatorio. Lo inserisce il
  rilascio dopo aver costruito e firmato le immagini (`PackagedPluginManifest`).

Il registry e la chiave di firma non compaiono nel contratto (D-0005 aperta).
"""

import re
from enum import StrEnum
from typing import Annotated, Any, Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictInt,
    field_validator,
    model_validator,
)
from pydantic.config import JsonDict

from ca_core.formats import ADMITTED_CYCLONEDX_VERSIONS
from ca_core.models.finding import Category

# Percorsi nel container, fissati dal contratto e non dal manifest (ADR-0004: argomenti a lista,
# nessuna scelta del plugin sui montaggi). Tutti in sola lettura tranne `/out`.
WORKSPACE_MOUNT = "/workspace"
SBOM_MOUNT = "/inputs/sbom.cdx.json"
CONFIG_MOUNT = "/inputs/config.json"
FEEDS_MOUNT: Literal["/feeds"] = "/feeds"
OUT_DIR = "/out"

_NAME = r"[a-z0-9]+(?:[._-][a-z0-9]+)*"
_REPOSITORY = rf"{_NAME}(?::[0-9]+)?(?:/{_NAME})*"
_TAG = r"[A-Za-z0-9_][A-Za-z0-9._-]{0,127}"
_DIGEST = r"sha256:[0-9a-f]{64}"
IMAGE_PATTERN = rf"^{_REPOSITORY}:{_TAG}(?:@{_DIGEST})?$"
PACKAGED_IMAGE_PATTERN = rf"^{_REPOSITORY}:{_TAG}@{_DIGEST}$"
_SEMVER = (
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)
_OUTPUT_PATH = rf"^{OUT_DIR}/[A-Za-z0-9_][A-Za-z0-9._-]*$"  # un file al primo livello (ADR-0004)
_DURATION = r"^[1-9][0-9]*s$"
_UNIQUE: JsonDict = {"uniqueItems": True}
_LATEST = r":latest(?:@|$)"  # fuori da IMAGE_PATTERN: niente lookahead


class Capability(StrEnum):
    DETECT = "detect"
    FIX = "fix"
    ENRICH = "enrich"


class InputMode(StrEnum):
    NONE = "none"
    OPTIONAL = "optional"


class FeedEcosystem(StrEnum):
    """Elenco fisso (ADR-0006): mai ricavato dal repository analizzato. Fase 1: npm e PyPI."""

    NPM = "npm"
    PYPI = "PyPI"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Inputs(_Strict):
    workspace: Literal["readonly"] = Field(
        description=f"Montato in sola lettura in {WORKSPACE_MOUNT}."
    )
    sbom: InputMode = Field(
        default=InputMode.NONE,
        description=f"`optional`: l'SBOM CycloneDX 1.7 del prodotto è montato in {SBOM_MOUNT} "
        "se disponibile (secondo stadio, ADR-0007); assente altrimenti.",
        json_schema_extra={"x-mount-path": SBOM_MOUNT},
    )
    config: InputMode = Field(
        default=InputMode.NONE,
        description=f"`optional`: un solo file JSON regolare in {CONFIG_MOUNT}, prodotto "
        "dall'host dalla sola parte di configurazione pertinente al plugin; mai il file del "
        "repository (ADR-0014).",
        json_schema_extra={"x-mount-path": CONFIG_MOUNT},
    )


MAX_OUTPUT_BYTES = 268_435_456  # 256 MiB, tetto provvisorio da rivedere con X-04


class Outputs(_Strict):
    """File di output del plugin, in `/out`.

    Vincolo non espresso dallo schema: `sarif` e `cyclonedx`, se entrambi presenti, devono
    essere percorsi diversi (altrimenti due uscite sovrascriverebbero lo stesso file).
    """

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            # Almeno un'uscita, e `cyclonedx_version` se e solo se c'è l'SBOM.
            "anyOf": [
                {"properties": {"sarif": {"type": "string"}}, "required": ["sarif"]},
                {"properties": {"cyclonedx": {"type": "string"}}, "required": ["cyclonedx"]},
            ],
            "if": {"properties": {"cyclonedx": {"type": "string"}}, "required": ["cyclonedx"]},
            "then": {
                "properties": {"cyclonedx_version": {"type": "string"}},
                "required": ["cyclonedx_version"],
            },
            "else": {"properties": {"cyclonedx_version": {"type": "null"}}},
        },
    )

    sarif: str | None = Field(default=None, pattern=_OUTPUT_PATH)
    cyclonedx: str | None = Field(default=None, pattern=_OUTPUT_PATH)
    cyclonedx_version: str | None = Field(
        default=None,
        description="Versione CycloneDX emessa, tra quelle ammesse (ADR-0007).",
        json_schema_extra={"enum": [*ADMITTED_CYCLONEDX_VERSIONS, None]},
    )
    max_bytes: StrictInt = Field(
        ge=1,
        le=MAX_OUTPUT_BYTES,
        description="Limite obbligatorio per ogni file di output (ADR-0004): oltre, il plugin "
        "è fallito. Il valore si fissa misurando le fixture.",
    )

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if self.sarif is None and self.cyclonedx is None:
            raise ValueError("serve almeno un'uscita tra sarif e cyclonedx")
        if self.sarif is not None and self.sarif == self.cyclonedx:
            raise ValueError("sarif e cyclonedx devono essere file diversi")
        if self.cyclonedx is None and self.cyclonedx_version is not None:
            raise ValueError("cyclonedx_version senza cyclonedx")
        if self.cyclonedx is not None and self.cyclonedx_version not in (
            ADMITTED_CYCLONEDX_VERSIONS
        ):
            raise ValueError(f"cyclonedx_version deve essere tra {ADMITTED_CYCLONEDX_VERSIONS}")
        return self


class Resources(_Strict):
    cpu: str = Field(pattern=r"^(?:[1-9][0-9]*(?:\.[0-9]+)?|0\.[0-9]*[1-9][0-9]*)$")
    memory: str = Field(pattern=r"^[1-9][0-9]*(?:Mi|Gi)$")
    timeout: str = Field(pattern=_DURATION)
    pids: StrictInt = Field(ge=1, description="Limite di PID del container (ADR-0004).")


class Feeds(_Strict):
    """Sincronizzazione del database di vulnerabilità (ADR-0006), in un container a parte."""

    sync_command: list[str] = Field(
        min_length=1,
        description="Argv eseguito nella stessa immagine firmata, senza workspace e senza shell.",
    )
    ecosystems: list[FeedEcosystem] = Field(
        default_factory=list, json_schema_extra=_UNIQUE, description="Elenco fisso, non dal repo."
    )
    mount: Literal["/feeds"] = Field(
        default=FEEDS_MOUNT, description="Snapshot montato in sola lettura durante la scansione."
    )
    sync_timeout: str = Field(pattern=_DURATION)

    @field_validator("sync_command")
    @classmethod
    def _no_empty_argument(cls, value: list[str]) -> list[str]:
        if any(not argument for argument in value):
            raise ValueError("argomento vuoto in sync_command")
        return value


_EXAMPLE: dict[str, Any] = {
    "apiVersion": "code-analyzer/v1",
    "name": "semgrep",
    "version": "1.0.0",
    "image": "registry.invalid/ca-plugins/semgrep:1.0.0",
    "capabilities": ["detect"],
    "languages": ["python", "javascript"],
    "categories": ["sast"],
    "inputs": {"workspace": "readonly"},
    "outputs": {"sarif": "/out/results.sarif", "max_bytes": 52428800},
    "resources": {"cpu": "2", "memory": "2Gi", "timeout": "600s", "pids": 256},
    "network": "none",
}
_EXAMPLE_FULL: dict[str, Any] = {
    **_EXAMPLE,
    "name": "osv-scanner",
    "image": f"registry.invalid/ca-plugins/osv-scanner:1.0.0@sha256:{'0' * 64}",
    "languages": [],
    "categories": ["dependency"],
    "inputs": {"workspace": "readonly", "sbom": "none", "config": "none"},
    "outputs": {
        "sarif": "/out/results.sarif",
        "cyclonedx": "/out/sbom.cdx.json",
        "cyclonedx_version": "1.7",
        "max_bytes": 52428800,
    },
    "feeds": {
        "sync_command": ["osv-sync"],
        "ecosystems": ["npm", "PyPI"],
        "mount": "/feeds",
        "sync_timeout": "900s",
    },
}


_SBOM_RULE: dict[str, Any] = {
    # Un plugin che emette un SBOM è del primo stadio e non può riceverne uno (ADR-0007).
    "if": {
        "properties": {
            "outputs": {"properties": {"cyclonedx": {"type": "string"}}, "required": ["cyclonedx"]}
        },
        "required": ["outputs"],
    },
    "then": {"properties": {"inputs": {"properties": {"sbom": {"const": "none"}}}}},
}


class PluginManifest(_Strict):
    """Manifest sorgente. `network` è solo `none` in Fase 1: `feeds-only` arriva con i mirror.

    Regole non esprimibili in `pattern`: `image` non usa il tag `latest` (vale lo schema
    con `not`); `outputs.cyclonedx` non è ammesso con `inputs.sbom: optional`.
    """

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={"examples": [_EXAMPLE, _EXAMPLE_FULL], **_SBOM_RULE},
    )

    apiVersion: Literal["code-analyzer/v1"]  # noqa: N815 - nome del campo nel contratto
    name: str = Field(pattern=r"^[a-z][a-z0-9-]{0,62}$")
    version: str = Field(pattern=_SEMVER)
    image: str = Field(
        pattern=IMAGE_PATTERN,
        description="`registro/percorso:tag`, con `@sha256:` facoltativo nel manifest sorgente. "
        "Il tag `latest` è vietato.",
        json_schema_extra={"not": {"pattern": _LATEST}},
    )
    capabilities: list[Capability] = Field(min_length=1, json_schema_extra=_UNIQUE)
    languages: list[Annotated[str, Field(pattern=r"^[a-z][a-z0-9+#-]*$")]] = Field(
        description="Vuoto: il plugin non dipende dal linguaggio.", json_schema_extra=_UNIQUE
    )
    categories: list[Category] = Field(min_length=1, json_schema_extra=_UNIQUE)
    inputs: Inputs
    outputs: Outputs
    resources: Resources
    network: Literal["none"]
    feeds: Feeds | None = None

    @field_validator("image")
    @classmethod
    def _not_latest(cls, value: str) -> str:
        if re.search(_LATEST, value):
            raise ValueError("il tag latest è vietato")
        return value

    @model_validator(mode="after")
    def _cyclonedx_producer_takes_no_sbom(self) -> Self:
        if self.outputs.cyclonedx is not None and self.inputs.sbom is not InputMode.NONE:
            raise ValueError("outputs.cyclonedx è incompatibile con inputs.sbom: optional")
        return self

    @field_validator("capabilities", "categories", "languages")
    @classmethod
    def _unique(cls, value: list[Any]) -> list[Any]:
        if len(set(value)) != len(value):
            raise ValueError("elementi duplicati")
        return value


class PackagedPluginManifest(PluginManifest):
    """Manifest impacchettato nella CLI: l'immagine ha il digest (ADR-0005)."""

    image: str = Field(pattern=PACKAGED_IMAGE_PATTERN)


# Definizione della forma impacchettata dentro lo schema `plugin-manifest` (stesso file, ADR-0003):
# i consumatori la validano con `urn:code-analyzer:schema:plugin-manifest:v1#/$defs/<nome>`.
PACKAGED_DEF_NAME = "PackagedPluginManifest"
PACKAGED_DEF: dict[str, Any] = {
    "allOf": [{"$ref": "#"}],
    "properties": {"image": {"pattern": PACKAGED_IMAGE_PATTERN}},
    "required": ["image"],
    "description": "Manifest impacchettato: come il sorgente, con `@sha256:` obbligatorio.",
}

"""Contratto delle proprietà SARIF dei plugin (ADR-0007). Solo dati.

Descrive il `properties` di un `result` SARIF scritto dagli adattatori nelle immagini, che non
importano `ca-core`: lo schema esportato è l'unico contratto che condividono. Il generatore sta
qui, il consumatore è la normalizzazione.

L'oggetto è chiuso: l'adattatore scrive solo queste chiavi e scarta quelle dello scanner
(`security-severity`, `tags`, ...), che altrimenti arriverebbero non fidate alla CLI.
"""

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StrictFloat, field_validator

from ca_core.models.finding import Category

_SHORT = Annotated[str, Field(min_length=1, max_length=256)]


class Cvss(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: str = Field(pattern=r"^(?:2\.0|3\.0|3\.1|4\.0)$")
    vector: str = Field(min_length=1, max_length=256)
    score: StrictFloat = Field(ge=0, le=10)  # stretto: lo schema rifiuta "9"


class PluginSarifProperties(BaseModel):
    model_config = ConfigDict(extra="forbid")

    aliases: list[_SHORT] = Field(
        default_factory=list,
        json_schema_extra={"uniqueItems": True},
        description="Altri identificativi della stessa vulnerabilità (CVE, GHSA, ...).",
    )
    category: Category | None = Field(
        default=None,
        description="Categoria del finding. Obbligatoria se il manifest del plugin dichiara "
        "più categorie (oggi trivy): lo schema non lo esprime, lo controlla la normalizzazione.",
    )
    cvss: Cvss | None = None
    secret_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
        description="SHA-256 del valore del segreto (ADR-0008), per il fingerprint. Non va "
        "propagato al report.",
    )
    tool_severity: _SHORT | None = Field(
        default=None, description="Severità dichiarata dallo scanner, non normalizzata."
    )
    license_spdx: _SHORT | None = Field(
        default=None, description="Identificativo o espressione SPDX."
    )
    purl: str | None = Field(default=None, pattern=r"^pkg:[a-z][a-z0-9.+-]*/\S+$", max_length=2048)

    @field_validator("aliases")
    @classmethod
    def _unique_aliases(cls, value: list[str]) -> list[str]:
        if len(set(value)) != len(value):
            raise ValueError("alias duplicati")
        return value

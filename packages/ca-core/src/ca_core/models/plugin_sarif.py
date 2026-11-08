"""Contratto delle proprietà SARIF dei plugin (ADR-0007). Solo dati.

Descrive il `properties` di un `result` SARIF scritto dagli adattatori nelle immagini, che non
importano `ca-core`: lo schema esportato è l'unico contratto che condividono. Il generatore sta
qui, il consumatore è la normalizzazione.
"""

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, field_validator

_SHORT = Annotated[str, Field(min_length=1, max_length=256)]


class Cvss(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: str = Field(pattern=r"^(?:2\.0|3\.0|3\.1|4\.0)$")
    vector: str = Field(min_length=1, max_length=256)
    score: float = Field(ge=0, le=10)


class PluginSarifProperties(BaseModel):
    """Chiavi note tipizzate; ogni altra chiave è ammessa e ignorata.

    Un `property bag` SARIF porta anche chiavi degli scanner (`security-severity`, `tags`):
    qui `extra="allow"` è voluto, a differenza degli altri contratti.
    """

    model_config = ConfigDict(extra="allow")

    aliases: list[_SHORT] = Field(
        default_factory=list,
        json_schema_extra={"uniqueItems": True},
        description="Altri identificativi della stessa vulnerabilità (CVE, GHSA, ...).",
    )
    cvss: Cvss | None = None
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

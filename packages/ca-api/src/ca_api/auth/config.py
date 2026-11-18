"""Emittenti fidati (B-04, ADR-0019). Nessun IdP è cablato nel codice: li elenca la configurazione.

Un emittente è di un utente o di una pipeline. L'indirizzo delle chiavi viene **solo da qui**, mai
dal token: un emittente sconosciuto non provoca alcuna richiesta in uscita. `https` obbligatorio,
salvo l'opzione di sviluppo, che il server segnala all'avvio.
"""

import json
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ca_api.models import Role

# Elenco fisso di algoritmi asimmetrici: `none` e quelli simmetrici sono sempre respinti.
ALLOWED_ALGORITHMS = (
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
    "ES256",
    "ES384",
    "EdDSA",
)
MAX_ISSUERS = 50


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


def _https(url: str, *, dev: bool) -> str:
    parts = urlsplit(url)
    ok = parts.scheme == "https" or (dev and parts.scheme == "http")
    if not ok or not parts.hostname or parts.username or parts.password or parts.fragment:
        raise ValueError("URL non ammesso: serve https, un host e nessuna credenziale")
    return url


class _Issuer(_Strict):
    issuer: Annotated[str, Field(min_length=1, max_length=500)]
    audience: Annotated[str, Field(min_length=1, max_length=500)]
    jwks_url: Annotated[str, Field(max_length=2000)]
    allow_insecure_dev: bool = Field(
        default=False, description="Solo sviluppo: ammette `http`; il server lo segnala all'avvio."
    )

    @model_validator(mode="after")
    def _urls(self) -> _Issuer:
        _https(self.issuer, dev=self.allow_insecure_dev)
        _https(self.jwks_url, dev=self.allow_insecure_dev)
        return self


class UserIssuer(_Issuer):
    kind: Literal["user"] = "user"
    tenant: Annotated[str, Field(min_length=1, max_length=100)]
    roles_claim: Annotated[str, Field(min_length=1, max_length=100)] = "groups"
    roles_map: dict[str, list[Role]] = Field(
        default_factory=dict, description="Valore del claim → ruoli del prodotto."
    )


class PipelineIssuer(_Issuer):
    kind: Literal["pipeline"] = "pipeline"
    provider: Literal["github", "gitlab"]
    owners: dict[str, str] = Field(
        description="Identificativo del proprietario nel provider → tenant. Fuori mappa: 403."
    )

    @field_validator("owners")
    @classmethod
    def _owners(cls, value: dict[str, str]) -> dict[str, str]:
        if not value or any(not k or not v for k, v in value.items()):
            raise ValueError("owners non può essere vuoto né avere voci vuote")
        return value


Issuer = Annotated[UserIssuer | PipelineIssuer, Field(discriminator="kind")]


class AuthSettings(_Strict):
    issuers: list[Issuer] = Field(default_factory=list, max_length=MAX_ISSUERS)
    clock_skew_seconds: int = Field(default=60, ge=0, le=300)
    max_token_lifetime_seconds: int = Field(default=3600, ge=60, le=86400)
    jwks_ttl_seconds: int = Field(default=300, ge=10, le=86400)
    jwks_min_refresh_seconds: int = Field(default=30, ge=1, le=3600)
    max_token_bytes: int = Field(default=16384, ge=512, le=65536)

    @model_validator(mode="after")
    def _unique_issuers(self) -> AuthSettings:
        names = [i.issuer for i in self.issuers]
        if len(set(names)) != len(names):
            raise ValueError("emittenti duplicati")
        return self

    @property
    def insecure(self) -> list[str]:
        """Emittenti configurati con l'opzione di sviluppo: il server li segnala all'avvio."""
        return [i.issuer for i in self.issuers if i.allow_insecure_dev]


def load_auth_settings(path: str | Path) -> AuthSettings:
    """Dal file di configurazione del server. Un errore non riporta il contenuto del file."""
    try:
        raw = Path(path).read_bytes()
        if len(raw) > 256 * 1024:
            raise ValueError("file troppo grande")
        return AuthSettings.model_validate(json.loads(raw))
    except (OSError, ValueError) as exc:
        raise ValueError("configurazione di autenticazione non valida") from exc

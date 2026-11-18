"""Formato di errore unico, `application/problem+json` (RFC 9457), ADR-0017.

Ogni 4xx e 5xx dell'API ha questo schema. Un errore non riporta mai il valore ricevuto, solo dove
si trova e cosa non va: il corpo di una richiesta può contenere finding e percorsi riservati. Un 500
non espone tracce né messaggi interni. I client decidono su `status` e `code`, mai sul testo.
"""

from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

PROBLEM_MEDIA_TYPE = "application/problem+json"


class ProblemCode(StrEnum):
    """Enum del contratto: aggiungere un valore a una risposta è incompatibile (ADR-0017)."""

    UNAUTHENTICATED = "unauthenticated"
    FORBIDDEN = "forbidden"
    NOT_FOUND = "not-found"
    VALIDATION_FAILED = "validation-failed"
    REPORT_SCHEMA_INVALID = "report-schema-invalid"
    PAYLOAD_TOO_LARGE = "payload-too-large"
    REPOSITORY_MISMATCH = "repository-mismatch"
    ARTIFACTS_CONFLICT = "artifacts-conflict"
    STATE_CONFLICT = "state-conflict"
    INVALID_CURSOR = "invalid-cursor"
    RATE_LIMITED = "rate-limited"
    NOT_IMPLEMENTED = "not-implemented"
    INTERNAL_ERROR = "internal-error"


class ProblemError(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pointer: Annotated[str, Field(max_length=512)] = Field(
        description="JSON Pointer nel corpo, oppure il nome del parametro."
    )
    message: Annotated[str, Field(max_length=500)] = Field(
        description="Cosa non va, mai il valore ricevuto."
    )


class Problem(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "examples": [
                {
                    "type": "about:blank",
                    "title": "Il report non è valido",
                    "status": 422,
                    "code": "report-schema-invalid",
                    "errors": [{"pointer": "/findings/0/level", "message": "valore non ammesso"}],
                }
            ]
        },
    )

    type: Annotated[str, Field(max_length=200)] = Field(
        default="about:blank", description="URI stabile del tipo di problema."
    )
    title: Annotated[str, Field(max_length=200)] = Field(
        description="Testo breve, uguale per ogni occorrenza del tipo."
    )
    status: Annotated[int, Field(ge=400, le=599)]
    code: ProblemCode
    detail: Annotated[str, Field(max_length=1000)] | None = None
    required_role: str | None = Field(
        default=None, description="Con un 403 per ruolo: il ruolo richiesto (ADR-0019)."
    )
    errors: list[ProblemError] | None = None


TITLES = {
    ProblemCode.UNAUTHENTICATED: "Autenticazione mancante o non valida",
    ProblemCode.FORBIDDEN: "Azione non permessa",
    ProblemCode.NOT_FOUND: "Risorsa non trovata",
    ProblemCode.VALIDATION_FAILED: "Richiesta non valida",
    ProblemCode.REPORT_SCHEMA_INVALID: "Un artefatto non è valido",
    ProblemCode.PAYLOAD_TOO_LARGE: "Richiesta troppo grande",
    ProblemCode.REPOSITORY_MISMATCH: "Il repository non coincide con quello del token",
    ProblemCode.ARTIFACTS_CONFLICT: "Artefatti diversi per lo stesso report",
    ProblemCode.STATE_CONFLICT: "Lo stato non lo permette",
    ProblemCode.INVALID_CURSOR: "Cursore non valido per questa richiesta",
    ProblemCode.RATE_LIMITED: "Troppe richieste",
    ProblemCode.NOT_IMPLEMENTED: "Non ancora realizzato",
    ProblemCode.INTERNAL_ERROR: "Errore interno",
}


class ApiProblem(Exception):
    """Un errore dell'API: lo converte in `Problem` il gestore dell'applicazione."""

    def __init__(
        self,
        status: int,
        code: ProblemCode,
        *,
        detail: str | None = None,
        required_role: str | None = None,
        errors: list[ProblemError] | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(code.value)
        self.headers = headers or {}
        self.problem = Problem(
            title=TITLES[code],
            status=status,
            code=code,
            detail=detail,
            required_role=required_role,
            errors=errors,
        )

"""Modelli dei dati che le integrazioni scrivono sui provider (C-09, ADR-0027). Solo dati.

Sono la forma, con i limiti, di ciò che N-02, N-03 e N-06 producono: nessuna logica di
composizione e nessuna chiamata di rete. Ogni campo di testo ha un tetto, così un testo del
repository analizzato (non fidato) non può far superare un limite del provider.
"""

from enum import StrEnum
from typing import Annotated, Self

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from ca_integrations import limits

PathStr = Annotated[
    str, StringConstraints(min_length=1, max_length=4096, pattern=r"^[^\x00-\x1f\x7f]+$")
]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Conclusion(StrEnum):
    """Come la regola di `gate` (ADR-0027): fallito, parziale, riuscito."""

    FAILURE = "failure"
    NEUTRAL = "neutral"
    SUCCESS = "success"


class AnnotationLevel(StrEnum):
    FAILURE = "failure"  # critico e alto
    WARNING = "warning"  # medio
    NOTICE = "notice"  # basso


class PullRequestComment(_Strict):
    """Un solo commento per PR, ritrovato dal marcatore (ADR-0027)."""

    marker: str = Field(pattern=r"^<!-- code-analyzer:[0-9]{1,20} -->$")
    body: Annotated[str, StringConstraints(max_length=limits.GITHUB_COMMENT_MAX_CHARS)]
    findings_shown: int = Field(ge=0, le=1000)
    findings_hidden: int = Field(ge=0)

    @model_validator(mode="after")
    def _marker_leads_and_is_unique(self) -> Self:
        if not self.body.startswith(self.marker) or self.body.count("code-analyzer:") != 1:
            raise ValueError("il corpo inizia con il marcatore, che compare una sola volta")
        return self


class Annotation(_Strict):
    path: PathStr
    start_line: int = Field(ge=1, le=10_000_000)
    end_line: int = Field(ge=1, le=10_000_000)
    level: AnnotationLevel
    title: Annotated[str, StringConstraints(max_length=limits.GITHUB_ANNOTATION_TITLE_MAX)]
    message: Annotated[
        str,
        StringConstraints(min_length=1, max_length=limits.GITHUB_ANNOTATION_MESSAGE_MAX_BYTES // 4),
    ]

    @model_validator(mode="after")
    def _ordered_and_small_in_bytes(self) -> Self:
        if self.end_line < self.start_line:
            raise ValueError("end_line prima di start_line")
        if len(self.message.encode()) > limits.GITHUB_ANNOTATION_MESSAGE_MAX_BYTES:
            raise ValueError("messaggio oltre il limite in byte")
        return self


class CheckRunOutput(_Strict):
    title: Annotated[str, StringConstraints(min_length=1, max_length=limits.GITHUB_CHECK_TITLE_MAX)]
    summary: Annotated[str, StringConstraints(max_length=limits.GITHUB_CHECK_SUMMARY_MAX_CHARS)]
    annotations: list[Annotation] = Field(
        default_factory=list, max_length=limits.GITHUB_ANNOTATIONS_PER_REQUEST
    )


class CheckRun(_Strict):
    conclusion: Conclusion
    output: CheckRunOutput


class CodeQualityLines(_Strict):
    begin: int = Field(ge=1, le=10_000_000)


class CodeQualityLocation(_Strict):
    path: PathStr
    lines: CodeQualityLines


class CodeQualityIssue(_Strict):
    """Un elemento del report `codequality` di GitLab (formato Code Climate)."""

    description: Annotated[
        str, StringConstraints(min_length=1, max_length=limits.GITLAB_DESCRIPTION_MAX)
    ]
    check_name: Annotated[str, StringConstraints(min_length=1, max_length=limits.GITLAB_NAME_MAX)]
    fingerprint: str = Field(
        pattern=r"^[0-9a-f]{32,64}$"
    )  # per GitLab, chiave tra una pipeline e l'altra
    severity: str = Field(pattern=r"^(?:info|minor|major|critical|blocker)$")
    location: CodeQualityLocation

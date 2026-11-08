"""Formati esterni ammessi in ingresso dal nucleo (ADR-0007, emendamento dopo V-09)."""

SARIF_VERSION = "2.1.0"

# Versioni CycloneDX che un manifest può dichiarare di emettere. La 1.6 si aggiunge qui, con
# lo schema in `schemas/vendor/`, solo se un manifest la richiede.
ADMITTED_CYCLONEDX_VERSIONS: tuple[str, ...] = ("1.7",)

"""Formati esterni ammessi in ingresso dal nucleo (ADR-0007, emendamento dopo V-09)."""

SARIF_VERSION = "2.1.0"

# Versioni CycloneDX che un manifest può dichiarare di emettere. La 1.6 si aggiunge qui, con
# lo schema in `schemas/vendor/`, solo se un manifest la richiede.
ADMITTED_CYCLONEDX_VERSIONS: tuple[str, ...] = ("1.7",)

# Versioni CycloneDX che solo i nostri export possono scrivere (N-06): GitLab accetta 1.4, 1.5 e 1.6
# per il suo report `cyclonedx`. Non si ammettono come ingresso né come dichiarazione di un plugin.
EXPORT_CYCLONEDX_VERSIONS: tuple[str, ...] = ("1.6",)

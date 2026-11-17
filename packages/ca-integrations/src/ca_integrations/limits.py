"""Limiti e versioni dei formati in uscita delle integrazioni (C-09, ADR-0027).

Due origini diverse, da non confondere:

- **GitLab**: i limiti dei report vengono dagli schemi fissati in `ca_core/vendor_schemas`
  (tag v15.2.5 di security-report-schemas): nome 255 caratteri, descrizione 1 MiB, soluzione
  7000. Sono verificati dai test di contratto contro lo schema, non solo qui.
- **GitHub**: i limiti di commenti e check run sono quelli della documentazione delle API,
  riportati qui a memoria e **da verificare alla fonte in N-02 e N-03** (ADR-0027). Un errore
  qui fa rifiutare la richiesta dal provider; nessun test locale lo può provare.
"""

from typing import Final

# --- GitLab -------------------------------------------------------------------------------------
GITLAB_SCHEMA_VERSION: Final = "15.2.5"  # `version` dei report sast e dependency_scanning
GITLAB_NAME_MAX: Final = 255
GITLAB_DESCRIPTION_MAX: Final = 1_048_576
GITLAB_SOLUTION_MAX: Final = 7000
# CycloneDX: il file è quello di `syft`, già 1.7 (ADR-0007). Le versioni che GitLab accetta per
# l'analisi delle dipendenze non sono state verificate: N-06 le legge dalla documentazione e, se
# 1.7 non è tra quelle, il report `cyclonedx` si pubblica comunque come artefatto generico.
GITLAB_CYCLONEDX_VERIFIED: Final = False

# Gravità del formato `codequality` (Code Climate) e del formato dei report di sicurezza.
CODEQUALITY_SEVERITIES: Final = ("info", "minor", "major", "critical", "blocker")
GITLAB_SEVERITIES: Final = ("Info", "Unknown", "Low", "Medium", "High", "Critical")

# --- GitHub (da verificare, N-02 e N-03) ----------------------------------------------------
GITHUB_COMMENT_MAX_CHARS: Final = 65_536
GITHUB_CHECK_TITLE_MAX: Final = 255
GITHUB_CHECK_SUMMARY_MAX_CHARS: Final = 65_535
GITHUB_ANNOTATIONS_PER_REQUEST: Final = 50
GITHUB_ANNOTATION_MESSAGE_MAX_BYTES: Final = 65_536
GITHUB_ANNOTATION_TITLE_MAX: Final = 255

# --- predefiniti del prodotto (ADR-0027: in configurazione; qui i valori di partenza) ---
DEFAULT_COMMENT_FINDINGS: Final = 20
DEFAULT_ANNOTATIONS: Final = 50

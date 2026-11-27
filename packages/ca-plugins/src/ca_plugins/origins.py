"""Da dove si scaricano i feed (E-04, ADR-0024, ADR-0006).

Per ogni feed l'origine viene, in quest'ordine, dal flag della CLI (`--feed-origin NOME=VALORE`),
dalla variabile d'ambiente e dal valore predefinito del pacchetto. **Mai** da `.code-analyzer.yml`
né da altro del repository analizzato (ADR-0014): chi controlla l'origine controlla i dati che
determinano il punteggio. Con un'origine diversa cambia solo l'origine: stessi controlli, stessa
cache. Nel report finisce un'etichetta (`public` o `mirror`), mai l'indirizzo, e i messaggi di
errore non ripetono il valore, che potrebbe contenere un segreto.

Nessuna autenticazione e nessuna verifica di firma: non c'è un mirror del prodotto (D2-05).
"""

import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from ca_plugins.enrichment import (
    EPSS_URL_ENV,
    KEV_URL_ENV,
    PUBLIC_EPSS,
    PUBLIC_KEV,
    Origin,
    check_url,
)

OSV_URL_ENV = "CA_FEEDS_OSV_URL"
TRIVY_DB_ENV = "CA_FEEDS_TRIVY_DB"
TRIVY_CHECKS_ENV = "CA_FEEDS_TRIVY_CHECKS"
ENVIRONMENT = {
    "epss": EPSS_URL_ENV,
    "kev": KEV_URL_ENV,
    "osv": OSV_URL_ENV,
    "trivy-db": TRIVY_DB_ENV,
    "trivy-checks": TRIVY_CHECKS_ENV,
}
# Il valore predefinito di OSV sta nell'adattatore, che non importa il nucleo (ADR-0007): qui serve
# solo a riconoscere chi lo indica per esteso. Un test li tiene uguali.
PUBLIC_OSV = "https://osv-vulnerabilities.storage.googleapis.com"
# Riferimento OCI: registro con un punto o una porta (o `localhost`), percorso, tag o digest
# facoltativi. Niente schema, credenziali, spazi, virgole (trivy le legge come elenco).
_OCI = re.compile(
    r"(?:localhost|[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+|[A-Za-z0-9-]+(?=:\d))(?::\d{1,5})?"
    r"(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)+"
    r"(?::[A-Za-z0-9_][A-Za-z0-9._-]{0,127})?(?:@sha256:[0-9a-f]{64})?"
)
_MAX_VALUE = 2048


class OriginError(ValueError):
    """Origine non valida. Il messaggio nomina il feed, mai il valore."""


@dataclass(frozen=True)
class FeedOrigins:
    enrichment: Origin = field(default_factory=Origin)
    osv_url: str | None = None  # None: il predefinito del pacchetto
    trivy_db: str | None = None
    trivy_checks: str | None = None

    def sync_args(self, plugin: str) -> tuple[str, ...]:
        """Le opzioni da aggiungere al comando di sincronizzazione del plugin; vuoto se
        l'origine è quella del pacchetto."""
        options: dict[str, list[tuple[str, str | None]]] = {
            "osv-scanner": [("--base-url", self.osv_url)],
            "trivy": [
                ("--db-repository", self.trivy_db),
                ("--checks-bundle-repository", self.trivy_checks),
            ],
        }
        return tuple(f"{name}={value}" for name, value in options.get(plugin, []) if value)


def _from_flags(flags: Sequence[str]) -> dict[str, str]:
    chosen: dict[str, str] = {}
    for item in flags:
        name, separator, value = item.partition("=")
        if name not in ENVIRONMENT:
            raise OriginError(f"--feed-origin: i nomi ammessi sono {', '.join(ENVIRONMENT)}")
        if not separator or not value:
            raise OriginError(f"--feed-origin {name}: manca il valore")
        if name in chosen:
            raise OriginError(f"--feed-origin {name}: indicato due volte")
        chosen[name] = value
    return chosen


def _url(name: str, value: str, *, allow_loopback_http: bool) -> str:
    try:
        if len(value) > _MAX_VALUE or any(c.isspace() or not c.isprintable() for c in value):
            raise ValueError
        return check_url(value, allow_loopback_http=allow_loopback_http)
    except ValueError:
        message = f"origine «{name}» non valida: serve un URL https senza credenziali"
        raise OriginError(message) from None


def _repository(name: str, value: str) -> str:
    if len(value) > _MAX_VALUE or not _OCI.fullmatch(value):
        message = f"origine «{name}» non valida: serve un riferimento OCI senza schema"
        raise OriginError(message)
    return value


def resolve_origins(
    flags: Sequence[str] = (),
    environ: Mapping[str, str] | None = None,
    *,
    allow_loopback_http: bool = False,
) -> FeedOrigins:
    """Le origini effettive; `OriginError` se un valore non è ammesso: meglio fermarsi che
    scaricare da un altro posto."""
    env = os.environ if environ is None else environ
    chosen = {name: env[var] for name, var in ENVIRONMENT.items() if env.get(var)}
    chosen.update(_from_flags(flags))

    def url(name: str) -> str | None:
        value = chosen.get(name)
        if value is None:
            return None
        return _url(name, value, allow_loopback_http=allow_loopback_http)

    osv = url("osv")
    if osv is not None:
        if "?" in osv:
            raise OriginError("origine «osv» non valida: è la base di un percorso, senza query")
        osv = osv.rstrip("/")
    return FeedOrigins(
        enrichment=Origin(url("epss") or PUBLIC_EPSS, url("kev") or PUBLIC_KEV),
        osv_url=None if osv == PUBLIC_OSV else osv,
        trivy_db=_repository("trivy-db", chosen["trivy-db"]) if "trivy-db" in chosen else None,
        trivy_checks=_repository("trivy-checks", chosen["trivy-checks"])
        if "trivy-checks" in chosen
        else None,
    )

"""Contesto del servizio e fattore C della Variante A (K-05, ADR-0028, ADR-0021).

Precedenza per singolo valore: file di contesto (`catalog`), poi il blocco `service` di
`.code-analyzer.yml` (`repository`, dichiarazione non verificata), poi il predefinito. Un valore
mancante non diventa favorevole: C senza tier vale quanto dice la configurazione (`c.missing`) e
l'evidenza dichiara la fonte `default`.
"""

from ca_core.models.config import Service
from ca_core.models.scan_report import ServiceContext, ServiceValue, Warning_
from ca_core.models.scoring_config import ScoringConfig
from ca_core.models.service_context_file import ServiceContextFile
from ca_core.scoring.base import Factor

DEFAULT_SERVICE = ServiceContext(
    tier=ServiceValue(value=None, source="default"),
    internet_facing=ServiceValue(value=None, source="default"),
)


def _pick(
    key: str, file: ServiceContextFile | None, declared: Service | None
) -> tuple[ServiceValue, bool]:
    """Il valore con la sua fonte, e se un valore dichiarato è stato scartato a favore del file."""
    from_file = getattr(file, key, None) if file is not None else None
    from_config = getattr(declared, key, None) if declared is not None else None
    if from_file is not None:
        return (
            ServiceValue(value=from_file, source="catalog"),
            from_config is not None and from_config != from_file,
        )
    if from_config is not None:
        return ServiceValue(value=from_config, source="repository"), False
    return ServiceValue(value=None, source="default"), False


def resolve_service_context(
    file: ServiceContextFile | None, declared: Service | None
) -> tuple[ServiceContext, list[Warning_]]:
    tier, tier_ignored = _pick("tier", file, declared)
    exposure, exposure_ignored = _pick("internet_facing", file, declared)
    catalog = None
    if file is not None and file.catalog_id is not None:
        catalog = file.catalog_id
    elif declared is not None:
        catalog = declared.catalog_id
    warnings: list[Warning_] = []
    if tier_ignored or exposure_ignored:
        warnings.append(
            Warning_(
                code="service-config-ignored",
                message="Il blocco `service` dice altro del file di contesto: vale il file.",
            )
        )
    if "repository" in (tier.source, exposure.source):
        warnings.append(
            Warning_(
                code="service-from-repository",
                message="Tier o esposizione dichiarati dal repository: non verificati.",
            )
        )
    context = ServiceContext(tier=tier, internet_facing=exposure, catalog_id=catalog)
    return context, warnings


def factor_c(service: ServiceContext, config: ScoringConfig) -> Factor:
    """C dal tier (1, 2, 3); tier assente: il valore `missing` della configurazione."""
    table = config.c
    tier = service.tier.value
    if isinstance(tier, bool) or tier not in (1, 2, 3):
        return Factor(table.missing, {"rule": "tier", "tier": None, "source": service.tier.source})
    value = {1: table.tier_1, 2: table.tier_2, 3: table.tier_3}[tier]
    return Factor(value, {"rule": "tier", "tier": tier, "source": service.tier.source})

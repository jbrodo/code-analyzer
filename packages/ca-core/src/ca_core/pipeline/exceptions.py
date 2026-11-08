"""Eccezioni (K-09, ADR-0014): un'eccezione con fingerprint corrispondente e `expires` non
superata imposta `status = accettato`.

`expires` è l'ultimo giorno valido, in UTC: oggi == `expires` vale ancora, il giorno dopo no.
Un'eccezione scaduta si ignora con l'avviso `exception-expired` (anche senza finding). Con più
eccezioni valide per lo stesso fingerprint vale quella che scade prima, la meno permissiva.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC

from ca_core.models.config import ConfigException
from ca_core.models.finding import Finding, Status
from ca_core.models.scan_report import AppliedException, Warning_
from ca_core.ports import Clock


@dataclass(frozen=True)
class ExceptionsResult:
    findings: list[Finding]
    applied: list[AppliedException]
    warnings: list[Warning_]


def apply_exceptions(
    findings: Sequence[Finding], exceptions: Sequence[ConfigException], clock: Clock
) -> ExceptionsResult:
    today = clock.now().astimezone(UTC).date()
    warnings: list[Warning_] = []
    valid: dict[str, ConfigException] = {}
    for exc in sorted(exceptions, key=lambda e: (e.fingerprint, e.expires, e.reason)):
        if exc.expires < today:
            warnings.append(
                Warning_(
                    code="exception-expired",
                    message=f"Eccezione scaduta il {exc.expires.isoformat()}: ignorata",
                    subject=exc.fingerprint,
                )
            )
        else:
            valid.setdefault(exc.fingerprint, exc)  # ordinate per scadenza: la prima vince
    present = {f.fingerprint for f in findings}
    out = [
        f.model_copy(update={"status": Status.ACCEPTED}) if f.fingerprint in valid else f
        for f in findings
    ]
    applied = [
        AppliedException(
            fingerprint=e.fingerprint,
            reason=e.reason,
            expires=e.expires,
            approved_by=e.approved_by,
        )
        for fp, e in sorted(valid.items())
        if fp in present
    ]
    return ExceptionsResult(out, applied, warnings)

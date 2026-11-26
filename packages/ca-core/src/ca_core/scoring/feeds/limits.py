"""Tetti e soglie della lettura dei feed EPSS e KEV (E-01, ADR-0024). Valori in `limits.json`.

I valori stanno nella configurazione del pacchetto, non nel codice e non in `.code-analyzer.yml`
(un repository non può cambiare i controlli sui dati che ne determinano il punteggio). Sono quelli
di partenza di ADR-0024, controllati sui file reali di V-05.
"""

from importlib import resources

from pydantic import BaseModel, ConfigDict, Field, StrictInt


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class EpssLimits(_Strict):
    max_download_bytes: StrictInt = Field(gt=0)
    max_decompressed_bytes: StrictInt = Field(gt=0)
    min_entries: StrictInt = Field(ge=0)
    max_entries: StrictInt = Field(gt=0)


class KevLimits(_Strict):
    max_download_bytes: StrictInt = Field(gt=0)
    min_entries: StrictInt = Field(ge=0)
    max_entries: StrictInt = Field(gt=0)


class FeedLimits(_Strict):
    version: StrictInt = Field(ge=1)
    epss: EpssLimits
    kev: KevLimits
    max_drop_percent: StrictInt = Field(ge=0, le=100, description="Calo massimo delle voci.")
    max_age_hours: StrictInt = Field(gt=0, description="Oltre, si risincronizza (ADR-0024).")


def load_limits() -> FeedLimits:
    raw = resources.files("ca_core.scoring.feeds").joinpath("limits.json").read_bytes()
    return FeedLimits.model_validate_json(raw)

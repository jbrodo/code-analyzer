"""Contratto `service-context`: il file di contesto del servizio passato a `scan` (ADR-0028, C-05).

Arriva da fuori dal repository analizzato, come la baseline (ADR-0025): lo scrive chi gestisce la
pipeline o il server. Ogni valore può mancare. Il testo è dato non fidato: niente caratteri di
controllo e lunghezza limitata.
"""

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt

_TEXT = Annotated[str, Field(max_length=200, pattern=r"^[^\x00-\x1f\x7f]*$")]


class ServiceContextFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: StrictInt = Field(ge=1, le=1, description="Versione del formato del file.")
    tier: StrictInt | None = Field(default=None, ge=1, le=3)
    internet_facing: StrictBool | None = None
    catalog_id: _TEXT | None = None
    origin: _TEXT | None = Field(
        default=None, description="Chi ha prodotto il file, dichiarato da chi lo scrive."
    )

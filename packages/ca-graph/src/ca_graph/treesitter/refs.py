"""Un import trovato in un file, prima della risoluzione (G-02, G-03)."""

from dataclasses import dataclass


@dataclass(frozen=True)
class ImportRef:
    """`spec` è la stringa dell'import; per Python il punto iniziale conta i livelli relativi.

    `names` sono i nomi importati con `from x import a, b` (possono essere sotto-moduli).
    """

    spec: str
    names: tuple[str, ...] = ()
    dynamic: bool = False
    type_only: bool = False


@dataclass
class FileImports:
    """Esito dell'analisi di un file: import risolvibili per testo e import calcolati."""

    refs: list[ImportRef]
    computed: int = 0  # argomento non letterale: nessun arco, solo un conteggio
    partial: bool = False  # errori di sintassi: gli import trovati si leggono, il file è parziale

"""Adattatore del plugin ca-graph (G-09). Estrae il grafo dei moduli del workspace (ADR-0020).

Gira nell'immagine con il profilo `hardened-container` (ADR-0004): `/workspace` in sola lettura,
`/out` scrivibile, `/tmp` tmpfs, nessuna rete. È l'unico punto in cui tree-sitter, un parser in C,
legge file del repository analizzato: un difetto nel parser o in una grammatica resta dentro il
container, con memoria e processi limitati. Il resto di `ca_graph` (metriche, smell, PageRank) gira
sull'host sui dati che questo plugin emette e non è nell'immagine.

Scrive `/out/graph.json` nel formato del contratto `graph` (C-02), serializzato in modo canonico.
Un limite globale superato o un'uscita oltre `max_bytes` è un fallimento, non un grafo troncato in
silenzio. Nessun output dello scanner arriva nei messaggi: i codici di uscita sono generici.

Uscite: 0 ok; 3 estrazione fallita (limite di file, errore di lettura, memoria); 5 grafo oltre il
limite di byte del manifest.
"""

import sys
from pathlib import Path

from ca_graph.treesitter.extract import extract_graph, to_json
from ca_graph.treesitter.files import LimitExceeded

WORKSPACE = "/workspace"
OUT_FILE = "/out/graph.json"
# Lo stesso valore di `outputs.max_bytes` in plugin.yaml: un grafo più grande fallisce qui, con un
# codice chiaro, invece di essere rifiutato dal runner come `invalid_output`.
MAX_BYTES = 64 * 1024 * 1024
EXIT_FAILED, EXIT_TOO_LARGE = 3, 5


def run(*, workspace: str = WORKSPACE, out_file: str = OUT_FILE, max_bytes: int = MAX_BYTES) -> int:
    try:
        data = to_json(extract_graph(workspace))
    except (LimitExceeded, OSError, MemoryError, RecursionError, ValueError):
        return EXIT_FAILED
    if len(data) > max_bytes:
        return EXIT_TOO_LARGE
    try:
        Path(out_file).write_bytes(data)
    except OSError:
        return EXIT_FAILED
    return 0


if __name__ == "__main__":
    sys.exit(run())

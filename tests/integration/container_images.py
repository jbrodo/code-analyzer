"""Immagini dei server di prova in container, tutte fissate per digest.

Un tag mobile (`latest`, `16`) cambia la prova senza un commit: è successo con SeaweedFS, che con
una configurazione predefinita dipendente dal disco falliva solo sul runner della CI. La guardia è
`tests/unit/test_container_images_pinned.py`.
"""

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]

# La stessa del compose di sviluppo (I-05): un'immagine sola da aggiornare.
POSTGRES: str = yaml.safe_load((ROOT / "deploy/compose/server-dev.yaml").read_text())["services"][
    "db"
]["image"]

# SeaweedFS 4.55, strumento di prova mai distribuito (ADR-0030).
SEAWEEDFS = (
    "chrislusf/seaweedfs:4.55"
    "@sha256:7ca46aeae2f223b37e5d91593c17ab37738eec6df6ab69b48a0487f7643342b9"
)

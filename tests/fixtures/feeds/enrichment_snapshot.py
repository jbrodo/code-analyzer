"""F-04: snapshot congelato e ridotto di EPSS e KEV (ADR-0024, §16 regola 7). Nessuna rete.

I due file in `enrichment/` sono la riduzione dei feed pubblici del 2026-11-17 ai CVE delle fixture
(`tests/fixtures/repos/*/expected-findings.yaml`) più due CVE reali di controllo. I valori EPSS sono
quelli pubblicati quel giorno; le voci KEV sono reali **tranne** quelle in `SYNTHETIC_KEV`: nessun
CVE delle fixture è nel catalogo, e la prova del ramo KEV ne richiede qualcuno. Vedi `README.md`.

Due modi d'uso:

- `snapshot_feeds()`: la porta `EnrichmentFeeds` già pronta, per i test dello scoring in processo;
- `seed_cache(dir, downloaded_at)`: la stessa cosa scritta nella cache per utente della CLI
  (`<cache>/enrichment/<feed>/current.json` e `snap-*/data`), da leggere con `load_enrichment` e
  `LIMITS`. I limiti di produzione (`limits.json`) rifiutano uno snapshot così piccolo per
  plausibilità: è voluto, quindi questo snapshot non vale per una CLI lanciata senza `LIMITS`.
"""

import hashlib
import json
import os
from datetime import datetime
from pathlib import Path

from ca_core.scoring.feeds.limits import EpssLimits, FeedLimits, KevLimits
from ca_core.scoring.feeds.parse import parse_epss, parse_kev
from ca_core.scoring.feeds.snapshot import SnapshotFeeds

HERE = Path(__file__).parent / "enrichment"
EPSS_FILE = HERE / "epss_scores-2026-11-17.csv"
KEV_FILE = HERE / "known_exploited_vulnerabilities-2026-11-17.json"

SYNTHETIC_KEV = frozenset({"CVE-2021-44906", "CVE-2018-18074"})  # non sono in KEV: solo prova
EPSS_THRESHOLD = 0.1  # soglia dell'override EPSS di ADR-0021

LIMITS = FeedLimits(
    version=1,
    epss=EpssLimits(
        max_download_bytes=1 << 16, max_decompressed_bytes=1 << 16, min_entries=1, max_entries=100
    ),
    kev=KevLimits(max_download_bytes=1 << 16, min_entries=1, max_entries=100),
    max_drop_percent=20,
    max_age_hours=24,
)

_SNAP_DIRS = {"epss": "snap-f04epss0", "kev": "snap-f04kev00"}


def raw(feed: str) -> bytes:
    return (EPSS_FILE if feed == "epss" else KEV_FILE).read_bytes()


def snapshot_feeds() -> SnapshotFeeds:
    return SnapshotFeeds(
        parse_epss(raw("epss"), LIMITS.epss), parse_kev(raw("kev"), LIMITS.kev), snapshots=[]
    )


def seed_cache(cache_dir: Path, downloaded_at: datetime) -> None:
    """Scrive lo snapshot nella cache dei feed come farebbe una sincronizzazione riuscita."""
    for path in (cache_dir, cache_dir / "epss", cache_dir / "kev"):
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(path, 0o700)
    for feed, snap in _SNAP_DIRS.items():
        data = raw(feed)
        table = parse_epss(data, LIMITS.epss) if feed == "epss" else parse_kev(data, LIMITS.kev)
        (cache_dir / feed / snap).mkdir(mode=0o700)
        (cache_dir / feed / snap / "data").write_bytes(data)
        pointer = {
            "dir": snap,
            "downloaded_at": downloaded_at.isoformat(),
            "sha256": hashlib.sha256(data).hexdigest(),
            "origin": "public",
            "entries": len(table.entries),
        }
        (cache_dir / feed / "current.json").write_text(json.dumps(pointer))

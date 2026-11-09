"""Scansione di sviluppo di un repository qualsiasi con la CLI vera. Non e' un test.

Riusa il laboratorio degli E2E: costruisce e firma le immagini con una chiave di prova, le pubblica
su un registry locale, usa lo snapshot congelato dei feed (`--offline`) e rimuove tutto alla fine.
Serve finche' I-04 non produce manifest impacchettati veri, poi va tolto. Il repository analizzato
non viene toccato; report e SARIF restano in `--output-dir`.

Dalla radice del progetto, con le variabili degli E2E (`e2e_lab.py`: `COSIGN`, `SYFT`,
`CA_TEST_OSV_FEEDS`, `CA_TEST_TRIVY_FEEDS`):

    uv run python -m tests.e2e.scan_local PATH [--output-dir DIR] [--plugins a,b] [--timeout S]

Exit: quello di `scan` se fallisce, altrimenti quello di `gate` (0 superato, 1 fallito, 2 errore).
Alla fine i container del progetto vengono rimossi: per questo non parte se ce ne sono di attivi.
"""

import argparse
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path

from . import e2e_lab
from .conftest import ALL_PLUGINS
from .e2e_lab import Fleet, container_leftovers, make_feeds_cache

REPORT = "code-analyzer.report.json"


def missing_settings() -> list[str]:
    settings = {
        "COSIGN": e2e_lab.COSIGN,
        "SYFT": e2e_lab.SYFT,
        "CA_TEST_OSV_FEEDS": e2e_lab.OSV_FEEDS,
        "CA_TEST_TRIVY_FEEDS": e2e_lab.TRIVY_FEEDS,
    }
    return [name for name, value in settings.items() if not value]


def parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="scan_local", description=__doc__.splitlines()[0])
    parser.add_argument("path", type=Path, help="directory da analizzare")
    parser.add_argument("--output-dir", type=Path, default=Path("scan-out"))
    parser.add_argument("--plugins", default=",".join(ALL_PLUGINS), help="separati da virgola")
    parser.add_argument("--timeout", type=int, default=3600, help="secondi per la scansione")
    return parser.parse_args(argv)


def fail(message: str) -> int:
    print(f"scan_local: {message}", file=sys.stderr)
    return 2


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    plugins = [name.strip() for name in args.plugins.split(",") if name.strip()]
    if unknown := sorted(set(plugins) - set(ALL_PLUGINS)):
        return fail(f"plugin sconosciuti: {', '.join(unknown)}")
    if missing := missing_settings():
        return fail(f"variabili mancanti: {', '.join(missing)}")
    target = args.path.resolve()
    if not target.is_dir():
        return fail(f"non e' una directory: {target}")
    if container_leftovers():
        return fail("ci sono container del progetto attivi: attendi la fine dell'altra esecuzione")

    out_dir = args.output_dir.resolve()
    fleet = Fleet(work=Path(tempfile.mkdtemp(prefix="ca-scan-local-")))
    try:
        print(f"costruzione e firma di {len(plugins)} immagini...", file=sys.stderr)
        for plugin in {*plugins, "osv-scanner", "trivy"}:  # i digest servono alla cache dei feed
            fleet.add_builtin(plugin)
        cache = fleet.work / "feeds" / "cache"
        make_feeds_cache(cache, fleet.digests)
        print(f"scansione di {target}...", file=sys.stderr)
        scan = fleet.run(
            fleet.work, "scan", str(target), "--output-dir", str(out_dir), "--offline",
            plugins=plugins, feeds_cache=cache, timeout=args.timeout, out_dir=out_dir,
        )  # fmt: skip
        print(scan.stdout, end="")
        print(scan.stderr, end="", file=sys.stderr)
        print(f"durata della scansione: {scan.seconds} s", file=sys.stderr)
        if scan.returncode != 0:
            return scan.returncode
        gate = fleet.run(
            fleet.work, "gate", "--report", str(out_dir / REPORT), plugins=plugins
        )  # fmt: skip
        print(gate.stdout, end="")
        print(gate.stderr, end="", file=sys.stderr)
        return gate.returncode
    finally:
        fleet.close()


if __name__ == "__main__":
    sys.exit(main())

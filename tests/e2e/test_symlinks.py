"""N-10, N-10b (S-01): lockfile e sorgenti come symlink non azzerano gli scanner senza traccia.

Il repository ostile e' js-ts-app con `package-lock.json` e `src/server.ts` come symlink verso file
con altro nome (`real/lock.json`, `real/server.txt`). Controllo positivo: la scansione della
fixture pulita ha i finding di dipendenze e di semgrep, quella ostile no (il vettore e' attivo).
La traccia: `partial`, avviso `workspace-symlinks` col solo numero, riga su stderr, `gate` esce 2.
"""

from pathlib import Path

from .conftest import Scan, full_scan
from .e2e_lab import Fleet, copy_fixture, e2e_marks, needs_feeds

pytestmark = [*e2e_marks, needs_feeds]


def paths(scan: Scan) -> set[str]:
    return {f["location"].get("path", "") for f in scan.findings}


def test_symlinked_lockfile_and_source_are_declared_not_silently_dropped(
    fleet: Fleet, feeds_cache: Path, work: Path, jsts_scan: Scan
) -> None:
    clean = jsts_scan
    assert clean.report["status"] == "complete"
    assert any(f["category"] == "dependency" for f in clean.findings)  # controllo positivo
    assert "src/server.ts" in paths(clean)
    root = copy_fixture("js-ts-app", work / "links", license_policy=True)
    (root / "real").mkdir()
    (root / "package-lock.json").rename(root / "real/lock.json")
    (root / "src/server.ts").rename(root / "real/server.txt")
    (root / "package-lock.json").symlink_to("real/lock.json")
    (root / "src/server.ts").symlink_to("../real/server.txt")
    hostile = full_scan(fleet, feeds_cache, root, "js-ts-app-links", work)
    assert hostile.result.out_dir is not None
    result = hostile.result
    assert result.returncode == 0, result.stderr[-2000:]
    assert not any(f["category"] == "dependency" for f in hostile.findings)  # vettore attivo
    assert "src/server.ts" not in paths(hostile)
    report = hostile.report
    assert report["status"] == "partial"
    (warning,) = (w for w in report["warnings"] if w["code"] == "workspace-symlinks")
    text = "2 collegamenti simbolici a lockfile o sorgenti non analizzati: analisi incompleta"
    assert warning["message"] == text and text in result.stderr
    gate = fleet.run(
        root.parent, "gate", "--report", str(result.out_dir / "code-analyzer.report.json"),
        plugins=["osv-scanner"],
    )  # fmt: skip
    assert gate.returncode == 2

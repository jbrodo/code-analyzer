"""F-05: snapshot congelato dei feed di vulnerabilita' (ADR-0006, §16 regola 7).

Uno snapshot e' una cartella FUORI dal repository con questo aspetto, che e' anche quello che i
plugin vedono montato in `/feeds`:

    <snapshot>/osv-scalibr/npm/all.zip, osv-scalibr/PyPI/all.zip   (osv-scanner)
    <snapshot>/trivy/db/trivy.db, trivy/db/metadata.json, ...      (trivy)
    <snapshot>/SNAPSHOT.json                                       (data, versioni, SHA-256)

`freeze` lo produce da una cache per utente popolata dal prodotto (`code-analyzer scan` senza
`--offline`, cioe' `ensure_snapshot`) o da due cartelle gia' scaricate. `verify` ricalcola gli
SHA-256 e fallisce se un file manca, e' stato aggiunto o e' cambiato. Nessuna rete qui: la rete
serve solo al download che precede `freeze`. Vedi `README.md`.

Uso:
    python snapshot.py freeze --from-cache ~/.cache/code-analyzer/feeds --dest DEST
    python snapshot.py freeze --osv DIR --trivy DIR --dest DEST
    python snapshot.py verify DEST
"""

import argparse
import hashlib
import json
import os
import shutil
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

MANIFEST = "SNAPSHOT.json"
PLUGIN_TREES = {"osv-scanner": "osv-scalibr", "trivy": "trivy"}  # plugin -> cartella nello snapshot
REQUIRED = ("osv-scalibr/npm/all.zip", "osv-scalibr/PyPI/all.zip", "trivy/db/trivy.db")


class SnapshotError(Exception):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def _files(root: Path) -> list[Path]:
    found = []
    for current, dirs, names in os.walk(root, followlinks=False):
        for entry in [*dirs, *names]:
            if (Path(current) / entry).is_symlink():
                raise SnapshotError(f"symlink nello snapshot: {Path(current, entry)}")
        found += [Path(current) / n for n in names if not (Path(current) == root and n == MANIFEST)]
    return sorted(found)


def describe(root: Path) -> dict[str, dict[str, Any]]:
    return {
        p.relative_to(root).as_posix(): {"sha256": sha256_file(p), "size": p.stat().st_size}
        for p in _files(root)
    }


def current_snapshot_dir(cache: Path, plugin: str) -> Path:
    """Cartella `snap-*` indicata da `<cache>/<plugin>/current.json` (formato di `feeds.py`)."""
    try:
        pointer = json.loads((cache / plugin / "current.json").read_text(encoding="utf-8"))
        target = cache / plugin / str(pointer["dir"])
    except (OSError, ValueError, KeyError) as exc:
        raise SnapshotError(f"nessuno snapshot corrente per {plugin} in {cache}") from exc
    if not target.is_dir() or target.is_symlink():
        raise SnapshotError(f"snapshot di {plugin} non e' una cartella: {target.name}")
    return target


def _copy_tree(source: Path, dest: Path) -> None:
    if not source.is_dir():
        raise SnapshotError(f"manca {source}")
    shutil.copytree(source, dest, symlinks=False)


def freeze(*, osv: Path, trivy: Path, dest: Path, now: datetime | None = None) -> dict[str, Any]:
    """Copia `osv/osv-scalibr` e `trivy/trivy` in `dest` e scrive `SNAPSHOT.json`."""
    if dest.exists() and any(dest.iterdir()):
        raise SnapshotError(f"{dest} non e' vuota: uno snapshot non si sovrascrive")
    dest.mkdir(parents=True, exist_ok=True)
    _copy_tree(osv / "osv-scalibr", dest / "osv-scalibr")
    _copy_tree(trivy / "trivy", dest / "trivy")
    files = describe(dest)
    missing = [r for r in REQUIRED if r not in files]
    if missing:
        shutil.rmtree(dest)
        raise SnapshotError(f"file obbligatori assenti: {', '.join(missing)}")
    meta: dict[str, Any] = {}
    meta_file = dest / "trivy/db/metadata.json"
    if meta_file.is_file():
        meta = json.loads(meta_file.read_text(encoding="utf-8"))
    manifest = {
        "version": 1,
        "created_at": (now or datetime.now(UTC)).isoformat(),
        "trivy_db_updated_at": meta.get("UpdatedAt"),
        "files": files,
    }
    (dest / MANIFEST).write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    return manifest


def verify(root: Path, only: tuple[str, ...] = ()) -> dict[str, Any]:
    """Controlla `SNAPSHOT.json` contro i file. `only`: prefissi da controllare (es. `trivy/`)."""
    try:
        manifest = json.loads((root / MANIFEST).read_text(encoding="utf-8"))
        recorded: dict[str, dict[str, Any]] = manifest["files"]
    except (OSError, ValueError, KeyError) as exc:
        raise SnapshotError(f"{MANIFEST} assente o non valido in {root}") from exc
    wanted = {k: v for k, v in recorded.items() if not only or k.startswith(only)}
    problems = []
    for rel, info in sorted(wanted.items()):
        path = root / rel
        if not path.is_file() or path.is_symlink():
            problems.append(f"manca {rel}")
        elif path.stat().st_size != info["size"] or sha256_file(path) != info["sha256"]:
            problems.append(f"checksum diverso: {rel}")
    if not only:
        extra = sorted(set(describe(root)) - set(recorded))
        problems += [f"file non registrato: {rel}" for rel in extra]
    if problems:
        raise SnapshotError("; ".join(problems))
    return manifest  # type: ignore[no-any-return]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    fz = sub.add_parser("freeze")
    fz.add_argument("--dest", type=Path, required=True)
    fz.add_argument("--from-cache", type=Path)
    fz.add_argument("--osv", type=Path)
    fz.add_argument("--trivy", type=Path)
    vf = sub.add_parser("verify")
    vf.add_argument("snapshot", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "verify":
            manifest = verify(args.snapshot)
            print(f"ok: {len(manifest['files'])} file, creato {manifest['created_at']}")
            return 0
        if args.from_cache:
            osv = current_snapshot_dir(args.from_cache, "osv-scanner")
            trivy = current_snapshot_dir(args.from_cache, "trivy")
        elif args.osv and args.trivy:
            osv, trivy = args.osv, args.trivy
        else:
            parser.error("serve --from-cache oppure --osv e --trivy")
        manifest = freeze(osv=osv, trivy=trivy, dest=args.dest)
        print(f"snapshot in {args.dest}: {len(manifest['files'])} file, {manifest['created_at']}")
        return 0
    except SnapshotError as exc:
        print(f"snapshot: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

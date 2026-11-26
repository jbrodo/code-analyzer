"""F-05: la procedura di congelamento e di verifica dello snapshot (file piccoli, senza rete)."""

import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import snapshot  # noqa: E402


def make_sources(tmp_path: Path) -> tuple[Path, Path]:
    osv, trivy = tmp_path / "osv", tmp_path / "trivy-src"
    for eco in ("npm", "PyPI"):
        (osv / "osv-scalibr" / eco).mkdir(parents=True)
        (osv / "osv-scalibr" / eco / "all.zip").write_bytes(eco.encode())
    (trivy / "trivy/db").mkdir(parents=True)
    (trivy / "trivy/db/trivy.db").write_bytes(b"db")
    (trivy / "trivy/db/metadata.json").write_text(json.dumps({"UpdatedAt": "2026-11-08T12:51:20Z"}))
    for feed in snapshot.FEEDS:
        folder = tmp_path / "enrichment" / feed
        (folder / "snap-current0").mkdir(parents=True)
        (folder / "snap-current0/data").write_bytes(feed.encode())
        (folder / "snap-old00000").mkdir()  # residuo di una sincronizzazione precedente
        (folder / "snap-old00000/data").write_bytes(b"vecchio")
        (folder / "current.json").write_text(json.dumps({"dir": "snap-current0"}))
    return osv, trivy


def freeze(tmp_path: Path, dest: Path, **kwargs: object) -> dict[str, object]:
    osv, trivy = make_sources(tmp_path)
    return snapshot.freeze(
        osv=osv, trivy=trivy, enrichment=tmp_path / "enrichment", dest=dest, **kwargs
    )


def test_freeze_records_date_and_checksums_and_verify_passes(tmp_path: Path) -> None:
    when = datetime(2026, 11, 8, 16, tzinfo=UTC)
    manifest = freeze(tmp_path, tmp_path / "snap", now=when)
    assert manifest["created_at"] == when.isoformat()
    assert manifest["trivy_db_updated_at"] == "2026-11-08T12:51:20Z"
    assert set(snapshot.REQUIRED) <= set(manifest["files"])
    assert snapshot.verify(tmp_path / "snap")["files"] == manifest["files"]


@pytest.mark.parametrize("damage", ["change", "delete", "add", "symlink"])
def test_verify_rejects_any_difference(tmp_path: Path, damage: str) -> None:
    root = tmp_path / "snap"
    freeze(tmp_path, root)
    if damage == "change":
        (root / "trivy/db/trivy.db").write_bytes(b"DB")
    elif damage == "delete":
        (root / "osv-scalibr/npm/all.zip").unlink()
    elif damage == "add":
        (root / "extra").write_text("x")
    else:
        (root / "link").symlink_to(root / "trivy")
    with pytest.raises(snapshot.SnapshotError):
        snapshot.verify(root)


def test_verify_only_a_subtree_ignores_other_damage(tmp_path: Path) -> None:
    root = tmp_path / "snap"
    freeze(tmp_path, root)
    (root / "trivy/db/trivy.db").write_bytes(b"DB")
    snapshot.verify(root, only=("osv-scalibr/",))
    with pytest.raises(snapshot.SnapshotError, match="checksum diverso"):
        snapshot.verify(root, only=("trivy/",))


def test_freeze_refuses_incomplete_sources_and_nonempty_dest(tmp_path: Path) -> None:
    osv, trivy = make_sources(tmp_path)
    (trivy / "trivy/db/trivy.db").unlink()
    with pytest.raises(snapshot.SnapshotError, match="trivy.db"):
        snapshot.freeze(
            osv=osv, trivy=trivy, enrichment=tmp_path / "enrichment", dest=tmp_path / "snap"
        )
    assert not (tmp_path / "snap").exists()
    busy = tmp_path / "busy"
    busy.mkdir()
    (busy / "x").write_text("x")
    with pytest.raises(snapshot.SnapshotError, match="non e' vuota"):
        freeze(tmp_path / "again", busy)


def test_current_snapshot_dir_follows_the_product_pointer(tmp_path: Path) -> None:
    plugin = tmp_path / "trivy"
    (plugin / "snap-abcd1234").mkdir(parents=True)
    (plugin / "current.json").write_text(json.dumps({"dir": "snap-abcd1234"}))
    assert snapshot.current_snapshot_dir(tmp_path, "trivy") == plugin / "snap-abcd1234"
    with pytest.raises(snapshot.SnapshotError):
        snapshot.current_snapshot_dir(tmp_path, "osv-scanner")


def test_cli_freeze_and_verify(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    osv, trivy = make_sources(tmp_path)
    dest = str(tmp_path / "snap")
    sources = ["--osv", str(osv), "--trivy", str(trivy)]
    sources += ["--enrichment", str(tmp_path / "enrichment")]
    assert snapshot.main(["freeze", *sources, "--dest", dest]) == 0
    assert snapshot.main(["verify", dest]) == 0
    (Path(dest) / "osv-scalibr/PyPI/all.zip").write_bytes(b"x")
    assert snapshot.main(["verify", dest]) == 2
    assert "checksum diverso" in capsys.readouterr().err


def test_epss_and_kev_are_frozen_with_only_their_current_snapshot(tmp_path: Path) -> None:
    manifest = freeze(tmp_path, tmp_path / "snap")
    frozen = {k for k in manifest["files"] if k.startswith("enrichment/")}  # type: ignore[union-attr]
    assert frozen == {
        f"enrichment/{feed}/{name}"
        for feed in ("epss", "kev")
        for name in ("current.json", "snap-current0/data")
    }
    (tmp_path / "snap/enrichment/kev/snap-current0/data").write_bytes(b"altro")
    with pytest.raises(snapshot.SnapshotError, match="checksum diverso"):
        snapshot.verify(tmp_path / "snap", only=("enrichment/",))


@pytest.mark.parametrize("missing", ["epss/current.json", "kev/snap-current0/data"])
def test_a_snapshot_without_epss_or_kev_is_refused(tmp_path: Path, missing: str) -> None:
    osv, trivy = make_sources(tmp_path)
    (tmp_path / "enrichment" / missing).unlink()
    with pytest.raises(snapshot.SnapshotError):
        snapshot.freeze(
            osv=osv, trivy=trivy, enrichment=tmp_path / "enrichment", dest=tmp_path / "snap"
        )

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
    return osv, trivy


def test_freeze_records_date_and_checksums_and_verify_passes(tmp_path: Path) -> None:
    osv, trivy = make_sources(tmp_path)
    when = datetime(2026, 11, 8, 16, tzinfo=UTC)
    manifest = snapshot.freeze(osv=osv, trivy=trivy, dest=tmp_path / "snap", now=when)
    assert manifest["created_at"] == when.isoformat()
    assert manifest["trivy_db_updated_at"] == "2026-11-08T12:51:20Z"
    assert set(snapshot.REQUIRED) <= set(manifest["files"])
    assert snapshot.verify(tmp_path / "snap")["files"] == manifest["files"]


@pytest.mark.parametrize("damage", ["change", "delete", "add", "symlink"])
def test_verify_rejects_any_difference(tmp_path: Path, damage: str) -> None:
    osv, trivy = make_sources(tmp_path)
    root = tmp_path / "snap"
    snapshot.freeze(osv=osv, trivy=trivy, dest=root)
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
    osv, trivy = make_sources(tmp_path)
    root = tmp_path / "snap"
    snapshot.freeze(osv=osv, trivy=trivy, dest=root)
    (root / "trivy/db/trivy.db").write_bytes(b"DB")
    snapshot.verify(root, only=("osv-scalibr/",))
    with pytest.raises(snapshot.SnapshotError, match="checksum diverso"):
        snapshot.verify(root, only=("trivy/",))


def test_freeze_refuses_incomplete_sources_and_nonempty_dest(tmp_path: Path) -> None:
    osv, trivy = make_sources(tmp_path)
    (trivy / "trivy/db/trivy.db").unlink()
    with pytest.raises(snapshot.SnapshotError, match="trivy.db"):
        snapshot.freeze(osv=osv, trivy=trivy, dest=tmp_path / "snap")
    assert not (tmp_path / "snap").exists()
    full_osv, full_trivy = make_sources(tmp_path / "again")
    busy = tmp_path / "busy"
    busy.mkdir()
    (busy / "x").write_text("x")
    with pytest.raises(snapshot.SnapshotError, match="non e' vuota"):
        snapshot.freeze(osv=full_osv, trivy=full_trivy, dest=busy)


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
    assert snapshot.main(["freeze", "--osv", str(osv), "--trivy", str(trivy), "--dest", dest]) == 0
    assert snapshot.main(["verify", dest]) == 0
    (Path(dest) / "osv-scalibr/PyPI/all.zip").write_bytes(b"x")
    assert snapshot.main(["verify", dest]) == 2
    assert "checksum diverso" in capsys.readouterr().err

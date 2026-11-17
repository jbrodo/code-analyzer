"""F-03: i report di copertura di prova sono ben formati dove devono e ostili dove devono.

Il lettore è quello vero, l'adattatore del plugin coverage (P-05): la fixture e il plugin non
possono dire cose diverse. `expected.yaml` dà gli esiti, con i percorsi risolti rispetto a
`base_dir` e senza il controllo di esistenza nel workspace (le fixture non sono un repository).
"""

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

HERE = Path(__file__).resolve().parent
ADAPTER = (
    HERE.parents[2] / "packages/ca-plugins/src/ca_plugins/builtin/coverage/coverage_adapter.py"
)
_spec = importlib.util.spec_from_file_location("coverage_adapter", ADAPTER)
assert _spec and _spec.loader
adapter = importlib.util.module_from_spec(_spec)
sys.modules["coverage_adapter"] = adapter
_spec.loader.exec_module(adapter)

EXPECTED: dict[str, Any] = yaml.safe_load((HERE / "expected.yaml").read_text(encoding="utf-8"))
REPORTS = EXPECTED["reports"]


def read(name: str) -> tuple[dict[str, tuple[int, int]], int]:
    spec = REPORTS[name]
    entries = adapter.parse_report((HERE / name).read_bytes(), spec["format"])
    files: dict[str, dict[int, int]] = {}
    discarded = 0
    for filename, lines in entries:
        path = adapter.resolve(filename, spec.get("base_dir"))
        if path is None:
            discarded += 1
            continue
        target = files.setdefault(path, {})
        for number, hits in lines.items():
            target[number] = max(target.get(number, 0), hits)
    counts = {p: (len(v), sum(1 for h in v.values() if h > 0)) for p, v in files.items()}
    return counts, discarded


def test_every_report_on_disk_has_an_expectation_and_vice_versa() -> None:
    on_disk = {
        p.relative_to(HERE).as_posix()
        for sub in ("valid", "hostile")
        for p in (HERE / sub).iterdir()
    }
    assert on_disk == set(REPORTS)


@pytest.mark.parametrize("name", [n for n, r in REPORTS.items() if r["outcome"] == "read"])
def test_readable_reports_give_the_documented_counts(name: str) -> None:
    files, discarded = read(name)
    expected = REPORTS[name]
    assert files == {path: (c["measurable"], c["covered"]) for path, c in expected["files"].items()}
    assert discarded == expected.get("discarded_paths", 0)


@pytest.mark.parametrize("name", [n for n, r in REPORTS.items() if r["outcome"] == "empty"])
def test_empty_reports_are_valid(name: str) -> None:
    assert read(name) == ({}, 0)


@pytest.mark.parametrize("name", [n for n, r in REPORTS.items() if r["outcome"] == "refused"])
def test_hostile_reports_are_refused(name: str) -> None:
    with pytest.raises(adapter.ReportRefused):
        read(name)


def test_valid_reports_never_declare_entities_or_escape_the_workspace() -> None:
    for path in (HERE / "valid").iterdir():
        text = path.read_text(encoding="utf-8")
        assert "<!ENTITY" not in text
        assert "../" not in text and "SF:/" not in text


def test_hostile_encoded_reports_cannot_be_found_by_searching_the_text() -> None:
    """Il motivo del parser sui byte: una ricerca di `<!ENTITY` nei byte non li vede."""
    for name in ("cobertura-entity-utf16-bom.xml", "cobertura-entity-utf16le-nobom.xml"):
        data = (HERE / "hostile" / name).read_bytes()
        assert b"<!ENTITY" not in data
        with pytest.raises(adapter.ReportRefused):
            adapter.parse_cobertura(data)


def test_hostile_reports_contain_what_the_names_promise() -> None:
    entity = (HERE / "hostile/cobertura-entity.xml").read_text(encoding="utf-8")
    assert 'SYSTEM "file:///etc/passwd"' in entity
    laughs = (HERE / "hostile/cobertura-billion-laughs.xml").read_text(encoding="utf-8")
    assert laughs.count("<!ENTITY") == 3 and "&c;" in laughs
    assert "attacker.invalid" in (HERE / "hostile/cobertura-external-dtd.xml").read_text("utf-8")

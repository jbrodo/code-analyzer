"""T-04: output registrati degli adattatori dei plugin integrati (regola 4 di AGENTS.md).

Ogni plugin in `ca_plugins/builtin/<nome>/` (con `plugin.yaml`) porta in
`fixtures/output/` almeno un output reale registrato, e tutti gli output registrati devono
essere conformi. Finche' non esiste alcun plugin la prova e' vuota e il test `discovery`
dimostra, su un albero finto, che la convenzione trova i file e che un output non conforme
fa fallire.
"""

import json
from pathlib import Path

import pytest
from plugin_output_harness import BUILTIN, check_output, discover_adapter_outputs


def nonconforming(paths: list[Path]) -> dict[str, dict[str, list[str]]]:
    found: dict[str, dict[str, list[str]]] = {}
    for path in paths:
        try:
            problems = check_output(path)
        except ValueError as error:
            problems = {"format": [str(error)]}
        if problems:
            found[str(path)] = problems
    return found


def plugins_without_output(builtin: Path) -> list[str]:
    registered = {p.parent.parent.parent.name for p in discover_adapter_outputs(builtin)}
    declared = {p.parent.name for p in builtin.glob("*/plugin.yaml")}
    return sorted(declared - registered)


def test_registered_adapter_outputs_conform() -> None:
    assert nonconforming(discover_adapter_outputs()) == {}


def test_every_builtin_plugin_registers_an_output() -> None:
    assert plugins_without_output(BUILTIN) == []


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    good = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "t"}}, "results": []}]}
    for name, files in {
        "alpha": {"alpha.sarif": good},
        "beta": {"beta.sarif": {**good, "version": "2.0.0"}},
        "gamma": {},
    }.items():
        plugin = tmp_path / name
        plugin.mkdir()
        (plugin / "plugin.yaml").write_text("name: x\n", encoding="utf-8")
        if files:
            output = plugin / "fixtures" / "output"
            output.mkdir(parents=True)
            for fname, doc in files.items():
                (output / fname).write_text(json.dumps(doc), encoding="utf-8")
            (output / "notes.txt").write_text("ignorato", encoding="utf-8")
    return tmp_path


def test_discovery_finds_only_registered_outputs(tree: Path) -> None:
    assert [p.name for p in discover_adapter_outputs(tree)] == ["alpha.sarif", "beta.sarif"]


def test_discovery_on_missing_directory_is_empty(tmp_path: Path) -> None:
    assert discover_adapter_outputs(tmp_path / "missing") == []


def test_nonconforming_output_is_reported(tree: Path) -> None:
    found = nonconforming(discover_adapter_outputs(tree))
    assert [Path(k).name for k in found] == ["beta.sarif"]
    assert set(found[str(tree / "beta" / "fixtures" / "output" / "beta.sarif")]) == {"schema"}


def test_plugin_without_registered_output_is_reported(tree: Path) -> None:
    assert plugins_without_output(tree) == ["gamma"]

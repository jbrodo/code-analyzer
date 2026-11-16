"""T-02: l'harness di T-04 sui campioni reali di V-03 (`tests/fixtures/plugin-output/fase-2/`).

Stesse due letture di `test_recorded_samples.py`: l'output grezzo non e' conforme per motivi
registrati per nome, e un adattatore di prova con le sole trasformazioni di ADR-0007, ADR-0012 e
ADR-0026 lo rende conforme. Gli adattatori veri sono di P-01..P-05.

In piu' fissa i fatti di V-03 da cui quegli adattatori dipendono: il formato dei messaggi che
portano una metrica (ADR-0026: si riprova a ogni aggiornamento del motore), cio' che il JSON di
eslint contiene oltre ai messaggi, e la forma dei report di copertura.

Il grafo di `ca-graph` non e' qui: il suo schema nasce con C-02 e la sua prova con C-10.
"""

import copy
import json
import re
from pathlib import Path
from typing import Any

import pytest
from plugin_output_harness import SAMPLES, check_output, kind_of, load_json

FASE2 = SAMPLES / "fase-2"

# Gruppi di controlli che l'output grezzo non supera (V-03).
RAW_VERDICTS: dict[str, set[str]] = {
    "checkov.sarif": {"snippet"},  # testo della risorsa in region.snippet
    "eslint.formatter.sarif": {"uri"},  # file:///workspace/...; formattatore non usato (V-08)
    "hadolint.sarif": {"uri"},  # /workspace/Dockerfile
    "ruff.sarif": {"uri"},  # file:///workspace/..., anche dentro `fixes`
}
CATEGORY = {"ruff": "quality", "eslint": "quality", "checkov": "iac", "hadolint": "iac"}
# Chiavi che portano testo del file analizzato e non devono uscire dal container (ADR-0012).
CODE_KEYS = ("snippet", "fixes", "source", "suggestions", "insertedContent")

# Una espressione per regola (ADR-0026): valore misurato e soglia, nell'ordine dei gruppi.
RUFF_METRICS = {
    "C901": r"^`.+` is too complex \((\d+) > (\d+)\)$",
    "PLR0911": r"^Too many return statements \((\d+) > (\d+)\)$",
    "PLR0912": r"^Too many branches \((\d+) > (\d+)\)$",
    "PLR0913": r"^Too many arguments in function definition \((\d+) > (\d+)\)$",
    "PLR0915": r"^Too many statements \((\d+) > (\d+)\)$",
}
ESLINT_METRICS = {
    "complexity": r"^.+ has a complexity of (\d+)\. Maximum allowed is (\d+)\.$",
    "max-depth": r"^Blocks are nested too deeply \((\d+)\)\. Maximum allowed is (\d+)\.$",
    "max-lines-per-function": r"^.+ has too many lines \((\d+)\)\. Maximum allowed is (\d+)\.$",
    "max-params": r"^.+ has too many parameters \((\d+)\)\. Maximum allowed is (\d+)\.$",
}


def sample(name: str) -> Path:
    return FASE2 / name


def relative(uri: str) -> str:
    """Le quattro forme di V-03 ricondotte alla radice del workspace."""
    return re.sub(r"^(?:file://)?/?workspace/", "", uri)


def strip_code(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: strip_code(v) for k, v in value.items() if k not in CODE_KEYS}
    if isinstance(value, list):
        return [strip_code(v) for v in value]
    return value


def code_keys_in(value: Any) -> set[str]:
    if isinstance(value, dict):
        found = {k for k in value if k in CODE_KEYS}
        return found.union(*(code_keys_in(v) for v in value.values()))
    if isinstance(value, list):
        return set().union(*(code_keys_in(v) for v in value))
    return set()


def conform(document: dict[str, Any], plugin: str) -> dict[str, Any]:
    """Adattatore di prova per i SARIF nativi di ruff, checkov e hadolint."""
    doc = strip_code(copy.deepcopy(document))
    for run in doc["runs"]:
        for result in run.get("results", []):
            for location in result.get("locations", []):
                artifact = location["physicalLocation"]["artifactLocation"]
                artifact.pop("index", None)
                artifact["uri"] = relative(artifact["uri"])
            result["properties"] = {"category": CATEGORY[plugin]}
    return doc


def eslint_to_sarif(native: list[dict[str, Any]]) -> dict[str, Any]:
    """Adattatore di prova per il JSON nativo di eslint: niente formattatore esterno (V-08)."""
    results = [
        {
            "ruleId": message["ruleId"],
            "level": "error" if message["severity"] == 2 else "warning",
            "message": {"text": message["message"]},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": relative(entry["filePath"])},
                        "region": {"startLine": message["line"], "startColumn": message["column"]},
                    }
                }
            ],
            "properties": {
                "category": "quality",
                "tool_severity": "medium" if message["severity"] == 2 else "low",
            },
        }
        for entry in native
        for message in entry["messages"]
    ]
    return {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "eslint"}}, "results": results}],
    }


def write(tmp_path: Path, name: str, document: dict[str, Any]) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def results_of(document: dict[str, Any]) -> list[dict[str, Any]]:
    return document["runs"][0]["results"]


def uris_of(document: dict[str, Any]) -> set[str]:
    return {
        r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        for r in results_of(document)
    }


def metrics(
    messages: list[tuple[str, str]], patterns: dict[str, str]
) -> dict[str, list[tuple[int, int]]]:
    found: dict[str, list[tuple[int, int]]] = {}
    for rule, text in messages:
        if rule in patterns:
            match = re.fullmatch(patterns[rule], text)
            assert match is not None, f"{rule}: messaggio non riconosciuto: {text!r}"
            found.setdefault(rule, []).append((int(match[1]), int(match[2])))
    return found


@pytest.mark.parametrize("name", sorted(RAW_VERDICTS))
def test_raw_engine_output_fails_exactly_the_documented_checks(name: str) -> None:
    assert set(check_output(sample(name))) == RAW_VERDICTS[name]


def test_every_sarif_sample_has_a_documented_verdict() -> None:
    on_disk = {p.name for p in FASE2.iterdir() if kind_of(p) == "sarif"}
    assert on_disk == set(RAW_VERDICTS)


@pytest.mark.parametrize("plugin", ["checkov", "hadolint", "ruff"])
def test_native_sarif_passes_after_the_minimal_adaptation(plugin: str, tmp_path: Path) -> None:
    raw = load_json(sample(f"{plugin}.sarif"))
    adapted = conform(raw, plugin)
    assert check_output(write(tmp_path, f"{plugin}.sarif", adapted)) == {}
    assert len(results_of(adapted)) == len(results_of(raw)) > 0
    assert code_keys_in(adapted) == set()


def test_checkov_uri_looks_relative_but_is_rooted_at_the_file_system() -> None:
    """Il controllo `uri` non lo vede: `workspace/Dockerfile` e' un percorso relativo valido.

    L'adattatore di P-03 deve togliere il prefisso; qui resta scritto quali sono i percorsi veri.
    """
    raw = load_json(sample("checkov.sarif"))
    assert "uri" not in check_output(sample("checkov.sarif"))
    assert all(uri.startswith("workspace/") for uri in uris_of(raw))
    assert uris_of(conform(raw, "checkov")) == {"Dockerfile", "iac/k8s/pod.yaml", "iac/tf/main.tf"}


def test_checkov_and_ruff_give_no_usable_severity() -> None:
    """V-03: `level` sempre `error`. La severita' viene da una tabella del plugin (ADR-0026)."""
    for plugin in ("checkov", "ruff"):
        assert {r["level"] for r in results_of(load_json(sample(f"{plugin}.sarif")))} == {"error"}
    hadolint = {r["level"] for r in results_of(load_json(sample("hadolint.sarif")))}
    assert hadolint == {"error", "warning", "note"}


def test_eslint_native_json_is_not_a_plugin_output() -> None:
    path = sample("eslint.json")
    assert kind_of(path) == "native"
    with pytest.raises(ValueError, match="nativo"):
        check_output(path)


def test_eslint_native_json_carries_the_source_of_the_analysed_files() -> None:
    """Il JSON porta il testo intero di ogni file con messaggi, e il testo delle correzioni."""
    native = load_json(sample("eslint.json"))
    with_messages = [entry for entry in native if entry["messages"]]
    assert with_messages and all(entry["source"] for entry in with_messages)
    assert any("suggestions" in m for entry in native for m in entry["messages"])


def test_eslint_native_json_passes_after_conversion(tmp_path: Path) -> None:
    native = load_json(sample("eslint.json"))
    adapted = eslint_to_sarif(native)
    assert check_output(write(tmp_path, "eslint.sarif", adapted)) == {}
    assert code_keys_in(adapted) == set()
    # Stessi risultati del formattatore esterno, che non si usa: nulla si perde convertendo.
    formatter = load_json(sample("eslint.formatter.sarif"))
    assert sorted((r["ruleId"], r["message"]["text"]) for r in results_of(adapted)) == sorted(
        (r["ruleId"], r["message"]["text"]) for r in results_of(formatter)
    )
    assert uris_of(adapted) == {"web/src/plain.js", "web/src/sample.ts", "web/src/view.tsx"}


def test_ruff_metric_messages_match_one_expression_per_rule() -> None:
    messages = [
        (r["ruleId"], r["message"]["text"]) for r in results_of(load_json(sample("ruff.sarif")))
    ]
    assert metrics(messages, RUFF_METRICS) == {
        "C901": [(9, 3)],
        "PLR0911": [(6, 3)],
        "PLR0912": [(8, 3)],
        "PLR0913": [(7, 5)],
        "PLR0915": [(8, 5)],
    }


def test_eslint_metric_messages_match_one_expression_per_rule() -> None:
    native = load_json(sample("eslint.json"))
    messages = [(m["ruleId"], m["message"]) for entry in native for m in entry["messages"]]
    assert metrics(messages, ESLINT_METRICS) == {
        "complexity": [(7, 3)],
        "max-depth": [(3, 2)],
        "max-lines-per-function": [(18, 10)],
        "max-params": [(4, 3), (4, 3)],
    }


def lcov_records(name: str, tag: str) -> list[str]:
    lines = sample(name).read_text(encoding="utf-8").splitlines()
    return [line.split(":", 1)[1] for line in lines if line.startswith(f"{tag}:")]


def test_lcov_paths_are_relative_to_where_the_tests_ran() -> None:
    assert lcov_records("vitest.lcov", "SF") == ["src/calc.js"]
    python = lcov_records("coveragepy.lcov", "SF")
    assert "pkg/calc.py" in python and not any(path.startswith("/") for path in python)


def test_lcov_has_two_dialects_of_the_function_record() -> None:
    """coverage.py: riga iniziale, riga finale, nome. vitest: riga, nome, e un `TN:` vuoto."""
    assert all(len(r.split(",")) == 3 for r in lcov_records("coveragepy.lcov", "FN"))
    assert all(len(r.split(",")) == 2 for r in lcov_records("vitest.lcov", "FN"))
    assert lcov_records("vitest.lcov", "TN") == [""]
    assert lcov_records("coveragepy.lcov", "TN") == []


@pytest.mark.parametrize(
    ("name", "has_doctype"),
    [
        ("coveragepy.cobertura.xml", False),
        ("vitest.cobertura.xml", True),
        ("nyc-empty.cobertura.xml", True),
    ],
)
def test_cobertura_doctype_and_foreign_source_path(name: str, has_doctype: bool) -> None:
    """La DTD esterna non si carica mai; `<source>` e' un percorso di un'altra macchina."""
    text = sample(name).read_text(encoding="utf-8")
    assert ('<!DOCTYPE coverage SYSTEM "http://' in text) is has_doctype
    assert "<!ENTITY" not in text
    sources = re.findall(r"<source>([^<]*)</source>", text)
    assert sources and all(source.startswith("/") for source in sources)


def test_cobertura_empty_report_has_non_numeric_rates() -> None:
    text = sample("nyc-empty.cobertura.xml").read_text(encoding="utf-8")
    assert 'line-rate="NaN"' in text and "<class " not in text

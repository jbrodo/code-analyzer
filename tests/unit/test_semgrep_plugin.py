"""Plugin semgrep (P-10) senza Docker: manifest, adattatore, fixture registrate, Dockerfile.

Le regole sono in `builtin/semgrep/rules/` (P-09, `test_semgrep_rules.py`); le prove sull'immagine
reale sono in `tests/integration/test_semgrep_image.py`.
"""

import importlib.util
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml
from jsonschema import Draft202012Validator

from ca_core.models import PluginManifest

ROOT = Path(__file__).resolve().parents[2]
SEMGREP = ROOT / "packages/ca-plugins/src/ca_plugins/builtin/semgrep"
OUTPUTS = sorted((SEMGREP / "fixtures/output").glob("semgrep.*.sarif"))
WHEEL_SHA256 = "d847abb8fb6fdde77d9e30a6bc869dbfcb68eff4142dcd77897c52635a7600d9"  # V-01

_spec = importlib.util.spec_from_file_location("semgrep_adapter", SEMGREP / "semgrep_adapter.py")
assert _spec and _spec.loader
adapter = importlib.util.module_from_spec(_spec)
sys.modules["semgrep_adapter"] = adapter
_spec.loader.exec_module(adapter)

MANIFEST: dict[str, Any] = yaml.safe_load((SEMGREP / "plugin.yaml").read_text())


def raw_sarif(uri: str = "/workspace/src/a.py", **changes: Any) -> dict[str, Any]:
    document: dict[str, Any] = {
        "version": "2.1.0",
        "runs": [
            {
                "invocations": [{"executionSuccessful": True}],
                "results": [
                    {
                        "ruleId": "user.dotted.rule",
                        "fingerprints": {"matchBasedId/v1": "requires login"},
                        "message": {"text": 'found password "sentinel-xyz" in code'},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"},
                                    "region": {
                                        "startLine": 1,
                                        "snippet": {"text": 'PASSWORD = "sentinel-xyz"'},
                                    },
                                }
                            }
                        ],
                        "properties": {},
                    }
                ],
                "tool": {
                    "driver": {
                        "name": "Semgrep OSS",
                        "rules": [
                            {
                                "id": "user.dotted.rule",
                                "defaultConfiguration": {"level": "warning"},
                                "fullDescription": {"text": "found password $V in code"},
                            }
                        ],
                    }
                },
            }
        ],
    }
    return {**document, **changes}


# --- manifest ---------------------------------------------------------------------------


def test_manifest_valid_for_schema_and_model() -> None:
    schema = json.loads((ROOT / "schemas" / "plugin-manifest.schema.json").read_text())
    Draft202012Validator(schema).validate(MANIFEST)
    model = PluginManifest.model_validate(MANIFEST)
    assert (model.name, model.network, model.inputs.config) == ("semgrep", "none", "optional")
    assert model.outputs.sarif == "/out/results.sarif" and model.outputs.cyclonedx is None
    assert [c.value for c in model.categories] == ["sast"]
    assert set(model.languages) == {"python", "javascript", "typescript"}


def test_manifest_has_no_real_registry_and_no_digest() -> None:
    image = MANIFEST["image"]
    assert image.startswith("registry.invalid/") and "@" not in image  # D-0005 aperta
    assert not image.endswith(":latest")


def test_manifest_limits_are_documented_and_cover_the_measurements() -> None:
    text = (SEMGREP / "plugin.yaml").read_text()
    assert "X-02" in text and "17,4 s" in text
    assert MANIFEST["outputs"]["max_bytes"] >= 1000 * 4093  # massimo misurato (saleor)
    res = MANIFEST["resources"]
    assert (res["timeout"], res["pids"], res["memory"]) == ("120s", 64, "1Gi")


# --- fixture registrate ---------------------------------------------------------------------


def test_recorded_outputs_exist_for_both_fixture_repositories() -> None:
    assert [p.name for p in OUTPUTS] == ["semgrep.js-ts-app.sarif", "semgrep.python-app.sarif"]


@pytest.mark.parametrize("path", OUTPUTS, ids=lambda p: p.name)
def test_recorded_outputs_are_clean(path: Path) -> None:
    text = path.read_text()
    assert "/workspace" not in text and "/home/" not in text and "/tmp/" not in text
    assert "snippet" not in text and "uriBaseId" not in text and "requires login" not in text
    for result in json.loads(text)["runs"][0]["results"]:
        assert set(result["properties"]) == {"tool_severity"}
        assert result["ruleId"].startswith("ca-")  # senza prefisso di percorso


@pytest.mark.parametrize("repo", ["python-app", "js-ts-app"])
def test_recorded_outputs_equal_the_semgrep_expectations(repo: str) -> None:
    document = json.loads((SEMGREP / f"fixtures/output/semgrep.{repo}.sarif").read_text())
    found = set()
    for r in document["runs"][0]["results"]:
        physical = r["locations"][0]["physicalLocation"]
        found.add(
            (
                r["ruleId"],
                physical["artifactLocation"]["uri"],
                physical["region"]["startLine"],
                physical["region"]["endLine"],
            )
        )
    expected_file = ROOT / "tests/fixtures/repos" / repo / "expected-findings.yaml"
    expected = {
        (e["rule_id"], e["path"], e["start_line"], e["end_line"])
        for e in yaml.safe_load(expected_file.read_text())["expected"]
        if "semgrep" in e["tools"]
    }
    assert found == expected and expected


# --- adattatore: SARIF ------------------------------------------------------------------------


def test_adapt_makes_the_contract_output() -> None:
    out = json.loads(adapter.adapt(json.dumps(raw_sarif()).encode()))
    (result,) = out["runs"][0]["results"]
    assert result["ruleId"] == "user.dotted.rule"
    assert result["locations"][0]["physicalLocation"]["artifactLocation"] == {"uri": "src/a.py"}
    assert result["properties"] == {"tool_severity": "warning"}
    # il messaggio e' il testo della regola: la metavariabile non e' interpolata (niente codice)
    assert result["message"] == {"text": "found password $V in code"}
    text = json.dumps(out)
    assert "sentinel-xyz" not in text and "snippet" not in text and "fingerprints" not in text
    assert "/workspace" not in text and "uriBaseId" not in text


def test_adapt_without_rule_text_falls_back_to_the_rule_id() -> None:
    document = raw_sarif()
    document["runs"][0]["tool"]["driver"]["rules"] = []
    out = json.loads(adapter.adapt(json.dumps(document).encode()))
    assert out["runs"][0]["results"][0]["message"] == {"text": "user.dotted.rule"}
    assert out["runs"][0]["results"][0]["properties"] == {}


def test_adapt_keeps_a_relative_path_that_contains_the_word_workspace() -> None:
    out = json.loads(adapter.adapt(json.dumps(raw_sarif("/workspace/src/workspace/a.py")).encode()))
    location = out["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "src/workspace/a.py"


@pytest.mark.parametrize(
    "raw",
    [
        b"not json",
        b"[]",
        json.dumps(raw_sarif(version="2.0.0")).encode(),
        json.dumps(raw_sarif(runs=[])).encode(),
        json.dumps(raw_sarif("/etc/passwd")).encode(),
        json.dumps(raw_sarif("/workspace2/a.py")).encode(),
        json.dumps(raw_sarif(runs=[{"results": ["x"]}])).encode(),
    ],
    ids=["not-json", "not-object", "version", "no-run", "outside", "sibling-prefix", "bad-result"],
)
def test_adapt_rejects_what_it_cannot_make_conforming(raw: bytes) -> None:
    with pytest.raises(adapter.InvalidOutput):
        adapter.adapt(raw)


# --- adattatore: regole del repository ---------------------------------------------------------


def write_config(tmp_path: Path, data: Any) -> str:
    path = tmp_path / "config.json"
    path.write_text(json.dumps(data))
    return str(path)


def workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "ws"
    (ws / "rules").mkdir(parents=True)
    (ws / "rules/mine.yaml").write_text("rules: []\n")
    (tmp_path / "outside.yaml").write_text("rules: []\n")
    return ws


def test_user_rules_absent_config_means_no_rules(tmp_path: Path) -> None:
    assert adapter.user_rules(str(tmp_path / "none.json"), str(workspace(tmp_path))) == []


def test_user_rules_accepts_files_and_directories_inside_the_workspace(tmp_path: Path) -> None:
    ws = workspace(tmp_path)
    cfg = write_config(tmp_path, {"rules": ["rules", "rules/mine.yaml"]})
    assert adapter.user_rules(cfg, str(ws)) == [str(ws / "rules"), str(ws / "rules/mine.yaml")]


@pytest.mark.parametrize(
    "rules",
    [
        ["/etc/passwd"],
        ["../outside.yaml"],
        ["rules/../../outside.yaml"],
        ["missing.yaml"],
        ["."],
        [""],
        [3],
        "rules",
        ["rules"] * 51,
        ["bad\x00name"],
    ],
    ids=["absolute", "dotdot", "dotdot-inner", "missing", "root", "empty", "not-str", "not-list",
         "too-many", "nul"],
)  # fmt: skip
def test_user_rules_rejects_paths_that_escape_or_do_not_exist(tmp_path: Path, rules: Any) -> None:
    ws = workspace(tmp_path)
    with pytest.raises(adapter.InvalidConfig):
        adapter.user_rules(write_config(tmp_path, {"rules": rules}), str(ws))


def test_user_rules_rejects_a_symlink_that_leaves_the_workspace(tmp_path: Path) -> None:
    ws = workspace(tmp_path)
    os.symlink(tmp_path / "outside.yaml", ws / "link.yaml")
    os.symlink(tmp_path, ws / "dirlink")
    for name in ("link.yaml", "dirlink"):
        with pytest.raises(adapter.InvalidConfig):
            adapter.user_rules(write_config(tmp_path, {"rules": [name]}), str(ws))


@pytest.mark.parametrize("content", ["not json", "[]", '{"rules": 1}', '{"other": []}'])
def test_user_rules_rejects_a_malformed_config(tmp_path: Path, content: str) -> None:
    (tmp_path / "config.json").write_text(content)
    with pytest.raises(adapter.InvalidConfig):
        adapter.user_rules(str(tmp_path / "config.json"), str(workspace(tmp_path)))


def test_jobs_follow_the_cgroup_quota(tmp_path: Path) -> None:
    quota = tmp_path / "cpu.max"
    for text, expected in (("200000 100000\n", 2), ("150000 100000\n", 2), ("max 100000\n", 1)):
        quota.write_text(text)
        assert adapter.jobs(str(quota)) == expected
    assert adapter.jobs(str(tmp_path / "missing")) == 1


# --- adattatore: comando e uscite --------------------------------------------------------------


def test_command_uses_only_the_project_rules_and_the_safe_flags() -> None:
    argv = adapter.command("/s", [adapter.RULES], "/workspace", "/tmp/r.sarif", 2)
    assert argv.count("--config") == 1
    assert argv[argv.index("--config") + 1] == "/opt/ca-plugin/rules"
    assert {"--metrics=off", "--disable-version-check", "--no-git-ignore"} <= set(argv)
    assert {
        "--disable-nosem",
        "--max-target-bytes=0",  # N-11: nessun tetto di dimensione per file
        "--timeout=0",  # nessun tetto per regola: il tetto e' `resources.timeout`
        "--x-ignore-semgrepignore-files",
        "--no-rewrite-rule-ids",
        "--sarif",
    } <= set(argv)
    assert not any("auto" in a or "semgrep.dev" in a or a.startswith("p/") for a in argv)
    assert argv[-1] == "/workspace" and "--jobs=2" in argv


def fake_semgrep(tmp_path: Path, body: str) -> str:
    script = tmp_path / "semgrep"
    script.write_text(f"#!/bin/sh\n{body}\n")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return str(script)


def run_adapter(tmp_path: Path, body: str, config: str | None = None) -> tuple[int, Path]:
    out = tmp_path / "results.sarif"
    code = adapter.run(
        semgrep=fake_semgrep(tmp_path, body),
        workspace="/workspace",
        config_file=config or str(tmp_path / "none.json"),
        out_file=str(out),
        tmp_dir=str(tmp_path),
        njobs=1,
    )
    return code, out


def write_raw(document: dict[str, Any], exit_code: int = 0) -> str:
    # lo script scrive il SARIF nel file indicato da `--sarif-output=`
    loop = 'for a in "$@"; do case $a in --sarif-output=*) f=${a#--sarif-output=};; esac; done'
    return f"{loop}\ncat > \"$f\" <<'EOF'\n{json.dumps(document)}\nEOF\nexit {exit_code}"


def test_run_writes_the_adapted_file(tmp_path: Path) -> None:
    code, out = run_adapter(tmp_path, write_raw(raw_sarif()))
    assert code == 0
    assert json.loads(out.read_text())["runs"][0]["results"][0]["ruleId"] == "user.dotted.rule"


def test_run_passes_the_user_rules_to_semgrep(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "r.yaml").write_text("rules: []\n")
    args = tmp_path / "args"
    # il workspace e' fisso a /workspace nel fake, quindi si prova user_rules a parte e qui si
    # controlla solo che un config non valido non avvii semgrep
    code, _ = run_adapter(
        tmp_path, f"echo started > {args}", write_config(tmp_path, {"rules": ["../x"]})
    )
    assert code == adapter.EXIT_CONFIG and not args.exists()


def two_runs(tmp_path: Path, builtin_id: str, repo_id: str) -> tuple[int, Path, list[str]]:
    """Fake per `--config`: esito e configurazioni di ogni avvio."""
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "r.yaml").write_text("rules: []\n")

    def document(name: str, rule_id: str) -> Path:
        doc = raw_sarif(f"{ws}/src/a.py")
        doc["runs"][0]["tool"]["driver"]["rules"] = [{"id": rule_id}]
        doc["runs"][0]["results"][0]["ruleId"] = rule_id
        path = tmp_path / name
        path.write_text(json.dumps(doc))
        return path

    builtin, repo = document("builtin.json", builtin_id), document("repo.json", repo_id)
    log = tmp_path / "log"
    body = "\n".join(
        [
            'for a in "$@"; do case $a in --sarif-output=*) f=${a#--sarif-output=};; esac; done',
            f'echo "$2 $3" >> {log}',
            f'if [ "$3" = "{adapter.RULES}" ]; then cp {builtin} "$f"; else cp {repo} "$f"; fi',
        ]
    )
    out = tmp_path / "results.sarif"
    code = adapter.run(
        semgrep=fake_semgrep(tmp_path, body),
        workspace=str(ws),
        config_file=write_config(tmp_path, {"rules": ["r.yaml"]}),
        out_file=str(out),
        tmp_dir=str(tmp_path),
        njobs=1,
    )
    return code, out, log.read_text().splitlines()


def test_repository_rules_run_apart_and_results_are_merged(tmp_path: Path) -> None:
    code, out, calls = two_runs(tmp_path, "ca-py-x", "repo-x")
    assert code == 0
    assert calls == [
        f"--config {adapter.RULES}",
        f"--config {tmp_path.resolve()}/ws/r.yaml",
    ]  # N-26
    run = json.loads(out.read_text())["runs"][0]
    assert [r["ruleId"] for r in run["results"]] == ["ca-py-x", "repo-x"]
    assert [r["id"] for r in run["tool"]["driver"]["rules"]] == ["ca-py-x", "repo-x"]


def test_repository_rule_with_a_builtin_id_fails_the_plugin(tmp_path: Path) -> None:
    code, out, _ = two_runs(tmp_path, "ca-py-x", "ca-py-x")
    assert code == adapter.EXIT_CONFIG and not out.exists()


def test_run_tool_error_is_exit_3_and_writes_nothing(tmp_path: Path) -> None:
    code, out = run_adapter(tmp_path, write_raw(raw_sarif(), 7))
    assert (code, out.exists()) == (adapter.EXIT_TOOL, False)


def test_run_without_output_is_exit_3(tmp_path: Path) -> None:
    assert run_adapter(tmp_path, "exit 0")[0] == adapter.EXIT_TOOL


def test_run_missing_binary_is_exit_3(tmp_path: Path) -> None:
    code = adapter.run(
        semgrep=str(tmp_path / "nope"),
        config_file=str(tmp_path / "none.json"),
        out_file=str(tmp_path / "o"),
        tmp_dir=str(tmp_path),
    )
    assert code == adapter.EXIT_TOOL


def test_run_nonconforming_output_is_exit_5_and_writes_nothing(tmp_path: Path) -> None:
    code, out = run_adapter(tmp_path, write_raw(raw_sarif("/etc/passwd")))
    assert (code, out.exists()) == (adapter.EXIT_INVALID, False)


def test_run_never_leaks_stderr_or_stdout(
    tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    run_adapter(tmp_path, "echo token=abc; echo token=abc >&2; exit 7")
    assert capfd.readouterr() == ("", "")


def test_adapter_does_not_import_ca_core() -> None:
    text = (SEMGREP / "semgrep_adapter.py").read_text()
    assert not re.search(r"^\s*(?:from|import)\s+ca_", text, re.M)


# --- immagine (statico) -------------------------------------------------------------------


def test_dockerfile_pins_base_wheels_rules_and_labels() -> None:
    text = (SEMGREP / "Dockerfile").read_text()
    froms = re.findall(r"^FROM\s+(?:--platform=\S+\s+)?(\S+)", text, re.M)
    assert len(froms) == 2 and all(re.search(r"@sha256:[0-9a-f]{64}$", f) for f in froms)
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    assert "latest" not in code.lower()
    assert "--require-hashes" in text and "--only-binary=:all:" in text
    assert 'ca.engines="semgrep"' in text and "COPY rules/ /opt/ca-plugin/rules/" in text
    assert "SEMGREP_SEND_METRICS=off" in text and "org.opencontainers.image.licenses" not in text
    assert "USER 65534:65534" in text
    assert re.search(r'^ENTRYPOINT \["python", "/opt/ca-plugin/semgrep_adapter.py"\]$', text, re.M)


def test_lock_pins_semgrep_with_the_published_wheel_hash() -> None:
    lock = (SEMGREP / "requirements.lock").read_text()
    assert re.search(r"^semgrep==1\.184\.0 ", lock, re.M) and WHEEL_SHA256 in lock


def test_build_context_contains_only_what_the_image_needs() -> None:
    assert (SEMGREP / ".dockerignore").read_text().split() == [
        "*",
        "!semgrep_adapter.py",
        "!requirements.lock",
        "!licenses",
        "!rules",
    ]
    assert sorted(p.name for p in (SEMGREP / "rules").iterdir()) == [
        "javascript.yaml",
        "python.yaml",
    ]  # nessuna regola del registry


def test_license_files_state_lgpl_and_no_product_license() -> None:
    notices = " ".join((SEMGREP / "licenses/THIRD-PARTY-NOTICES.md").read_text().split())
    assert "LGPL-2.1" in notices and "non dichiara la licenza del prodotto" in notices.lower()
    assert "Semgrep Rules License" in notices  # le regole del registry non sono incluse
    licence = (SEMGREP / "licenses/semgrep/LICENSE").read_text()
    assert "GNU LESSER GENERAL PUBLIC LICENSE" in licence and "Version 2.1" in licence

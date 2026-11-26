"""Plugin semgrep (P-10) sull'immagine reale, con `OciExecutor` e il profilo completo. Opzionale.

`CA_TEST_DOCKER=1`; vedi `plugin_image_support.py` per `COSIGN` e `SYFT`. Costruisce
`localhost/ca-plugin-semgrep:itest` e la rimuove a fine sessione. L'esecuzione non usa la rete.
"""

import json
import re
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest
import yaml
from plugin_image_support import (
    BUILTIN,
    HARNESS,
    REPOS,
    build_image,
    gate,
    needs_cosign,
    needs_docker,
    needs_syft,
    run,
    run_ok,
    run_plugin,
    run_signed,
    signed_image,
)

from ca_core.ports import RunOutcome

PLUGIN = "semgrep"
TAG = "localhost/ca-plugin-semgrep:itest"
SENTINEL = "sentinel-hunter2-4f9a"
pytestmark = needs_docker


@pytest.fixture(scope="module")
def image_id() -> Iterator[str]:
    yield from build_image(PLUGIN, TAG)


def findings(raw: bytes) -> set[tuple[str, str, int, int]]:
    document = json.loads(raw)
    assert HARNESS.sarif_problems(document, PLUGIN) == {}
    found = set()
    for r in document["runs"][0]["results"]:
        physical = r["locations"][0]["physicalLocation"]
        region = physical["region"]
        found.add(
            (
                r["ruleId"],
                physical["artifactLocation"]["uri"],
                region["startLine"],
                region["endLine"],
            )
        )
    return found


def expected(repo: str) -> set[tuple[str, str, int, int]]:
    data = yaml.safe_load((REPOS / repo / "expected-findings.yaml").read_text())["expected"]
    return {
        (e["rule_id"], e["path"], e["start_line"], e["end_line"])
        for e in data
        if "semgrep" in e["tools"]
    }


@pytest.mark.parametrize("repo", ["python-app", "js-ts-app"])
def test_full_profile_finds_exactly_the_expected_sast_findings(
    image_id: str, tmp_path: Path, repo: str
) -> None:
    files = run_ok(PLUGIN, TAG, image_id, REPOS / repo, tmp_path)
    assert list(files) == ["results.sarif"]
    assert b"/workspace" not in files["results.sarif"]
    recorded = (BUILTIN / PLUGIN / f"fixtures/output/semgrep.{repo}.sarif").read_bytes()
    assert findings(files["results.sarif"]) == expected(repo) == findings(recorded)


def test_tests_directory_and_hostile_ignore_files_do_not_hide_findings(
    image_id: str, tmp_path: Path
) -> None:
    ws = tmp_path / "ws"
    (ws / "tests").mkdir(parents=True)
    source = (REPOS / "python-app/app/handlers.py").read_text()
    (ws / "tests/test_h.py").write_text(source)
    (ws / ".semgrepignore").write_text("*\n")  # repository ostile: ignora tutto
    (ws / ".gitignore").write_text("*\n")
    git = ws / ".git"
    git.mkdir()
    (git / "config").write_text("[core]\n\tfsmonitor = /bin/false\n")  # mai eseguito
    raw = run_ok(PLUGIN, TAG, image_id, ws, tmp_path / "w")["results.sarif"]
    assert {path for _, path, _, _ in findings(raw)} == {"tests/test_h.py"}
    assert {rule for rule, *_ in findings(raw)} >= {"ca-py-subprocess-shell", "ca-py-eval-dynamic"}


def write_repo_rules(ws: Path) -> None:
    (ws / "rules").mkdir(parents=True)
    (ws / "rules/mine.yaml").write_text(
        "rules:\n  - id: team.dotted.password\n    languages: [python]\n    severity: INFO\n"
        '    message: "found password $V in code"\n    pattern: PASSWORD = $V\n'
    )
    (ws / "app.py").write_text(f'PASSWORD = "{SENTINEL}"\n')


def test_repository_rules_run_and_never_leak_the_matched_code(
    image_id: str, tmp_path: Path
) -> None:
    ws = tmp_path / "ws"
    write_repo_rules(ws)
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps({"rules": ["rules/mine.yaml"]}))
    raw = run_ok(PLUGIN, TAG, image_id, ws, tmp_path / "w", config=str(cfg))["results.sarif"]
    assert SENTINEL.encode() not in raw  # ne' snippet ne' messaggio interpolato
    document = json.loads(raw)
    (result,) = document["runs"][0]["results"]
    assert result["ruleId"] == "team.dotted.password"  # id del file, senza prefisso di percorso
    assert result["message"]["text"] == "found password $V in code"
    assert result["properties"] == {"tool_severity": "note"}
    assert findings(raw) == {("team.dotted.password", "app.py", 1, 1)}


def test_without_the_config_the_repository_rules_are_not_used(
    image_id: str, tmp_path: Path
) -> None:
    ws = tmp_path / "ws"
    write_repo_rules(ws)
    raw = run_ok(PLUGIN, TAG, image_id, ws, tmp_path / "w")["results.sarif"]
    assert findings(raw) == set()


@pytest.mark.parametrize("rule", ["../escape.yaml", "/etc/passwd", "missing.yaml"])
def test_rule_outside_the_workspace_fails_the_plugin(
    image_id: str, tmp_path: Path, rule: str
) -> None:
    ws = tmp_path / "ws"
    write_repo_rules(ws)
    (tmp_path / "escape.yaml").write_text("rules: []\n")
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps({"rules": [rule]}))
    result, files = run_plugin(PLUGIN, TAG, image_id, ws, tmp_path / "w", config=str(cfg))
    assert result.outcome is RunOutcome.FAILED and files == {}


def test_invalid_repository_rule_fails_the_plugin(image_id: str, tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "bad.yaml").write_text("rules:\n  - id: x\n")
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps({"rules": ["bad.yaml"]}))
    result, _ = run_plugin(PLUGIN, TAG, image_id, ws, tmp_path / "w", config=str(cfg))
    assert result.outcome is RunOutcome.FAILED


def test_plugin_fails_when_the_workspace_cannot_be_read(image_id: str, tmp_path: Path) -> None:
    result, files = run_plugin(PLUGIN, TAG, image_id, tmp_path / "missing", tmp_path)
    assert result.outcome is RunOutcome.FAILED and files == {}


def test_positive_and_negative_cases_of_every_rule_with_the_image_engine(image_id: str) -> None:
    """P-09 nell'immagine: `semgrep --test` con il motore che si distribuisce. La prova con un
    semgrep installato (`test_semgrep_rules_real.py`) in CI si salta: senza questa, i casi di ogni
    regola non girerebbero mai."""
    cases = Path(__file__).resolve().parent / "semgrep_rule_cases"
    done = subprocess.run(
        ["docker", "run", "--rm", "--network", "none", "--read-only", "--tmpfs", "/tmp",
         "-e", "HOME=/tmp",
         "-v", f"{BUILTIN / PLUGIN / 'rules'}:/rules:ro", "-v", f"{cases}:/cases:ro",
         "--entrypoint", "/opt/venv/bin/semgrep", image_id,
         "--test", "--config", "/rules", "/cases",
         "--metrics=off", "--disable-version-check"],
        capture_output=True, text=True, check=False, timeout=600,
    )  # fmt: skip
    assert done.returncode == 0, (done.stdout + done.stderr)[-3000:]
    # «tutto verde» con zero regole provate non vale: l'esito nomina quante ne ha passate
    assert re.search(r"[1-9]\d*/[1-9]\d*: ✓", done.stdout), done.stdout[-2000:]
    assert "✖" not in done.stdout, done.stdout[-3000:]


def test_image_contains_only_the_project_rules(image_id: str) -> None:
    listing = run(
        "docker", "run", "--rm", "--network", "none", "--entrypoint", "find", image_id,
        "/opt/ca-plugin/rules", "-type", "f",
    )  # fmt: skip
    assert sorted(listing.split()) == [
        "/opt/ca-plugin/rules/javascript.yaml",
        "/opt/ca-plugin/rules/python.yaml",
    ]
    # nessun file di regole del registry altrove: cerca i YAML con `rules:` fuori da site-packages
    grep = "grep -rl --include='*.yaml' --include='*.yml' -E '^rules:' /opt /usr /home /root"
    others = subprocess.run(
        ["docker", "run", "--rm", "--network", "none", "--entrypoint", "sh", image_id, "-c", grep],
        capture_output=True, text=True, check=False,
    ).stdout.split()  # fmt: skip
    assert (
        "/opt/ca-plugin/rules/python.yaml" in others
    )  # controllo positivo: il grep trova le nostre
    assert [o for o in others if not o.startswith("/opt/ca-plugin/rules/")] == []


@needs_syft
def test_build_image_gate_checks_licenses_and_writes_the_image_sbom(tmp_path: Path) -> None:
    document = gate(PLUGIN, "localhost/ca-plugin-semgrep:gate", tmp_path)
    names = {c.get("name") for c in document["components"]}
    assert document["specVersion"] == "1.7" and "semgrep" in names


@needs_cosign
def test_signed_digest_is_verified_pulled_and_run(
    image_id: str, tmp_path_factory: pytest.TempPathFactory
) -> None:
    keys, work = tmp_path_factory.mktemp("keys"), tmp_path_factory.mktemp("w")  # fuori dal repo
    with signed_image(PLUGIN, "5062", "ca-p10-test", keys) as signed:
        raw = run_signed(PLUGIN, signed, REPOS / "js-ts-app", work)
    assert findings(raw) == expected("js-ts-app")


def test_a_file_over_one_megabyte_is_still_analyzed(image_id: str, tmp_path: Path) -> None:
    """N-11: semgrep salta i file oltre 1 MB; il riempimento non deve nascondere i finding."""
    ws = tmp_path / "ws"
    (ws / "app").mkdir(parents=True)
    source = (REPOS / "python-app/app/handlers.py").read_text()
    (ws / "app/handlers.py").write_text(source + "\n# " + "x" * 1_500_000 + "\n")
    (ws / "small.py").write_text(source)
    out = tmp_path / "direct"
    out.mkdir()
    out.chmod(0o777)
    cmd = [
        "docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
        "--user", "65534:65534", "--tmpfs", "/tmp:rw,noexec,nosuid", "--env", "HOME=/tmp",
        "--workdir", "/tmp", "--mount", f"type=bind,src={ws},dst=/workspace,readonly",
        "--mount", f"type=bind,src={out},dst=/out", "--entrypoint", "/opt/venv/bin/semgrep",
        image_id, "scan", "--config", "/opt/ca-plugin/rules", "--metrics=off",
        "--disable-version-check", "--quiet", "--no-git-ignore", "--sarif",
        "--sarif-output=/out/native.sarif", "/workspace",
    ]  # fmt: skip
    subprocess.run(cmd, capture_output=True, check=False, timeout=600)  # noqa: S603
    direct = json.loads((out / "native.sarif").read_text())["runs"][0]["results"]
    paths = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in direct}
    assert not any(p.endswith("app/handlers.py") for p in paths)  # controllo positivo: saltato
    assert any(p.endswith("small.py") for p in paths)
    raw = run_ok(PLUGIN, TAG, image_id, ws, tmp_path / "w")["results.sarif"]
    assert {path for _, path, _, _ in findings(raw)} == {"app/handlers.py", "small.py"}

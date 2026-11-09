"""P-09 con il semgrep reale (offline). Saltato se il binario manca: `CA_SEMGREP` o PATH."""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
SEMGREP_DIR = ROOT / "packages/ca-plugins/src/ca_plugins/builtin/semgrep"
CASES = Path(__file__).resolve().parent / "semgrep_rule_cases"
BINARY = os.environ.get("CA_SEMGREP") or shutil.which("semgrep")
pytestmark = pytest.mark.skipif(BINARY is None, reason="semgrep non disponibile")
FLAGS = ["--metrics=off", "--disable-version-check", "--quiet"]


def semgrep(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    assert BINARY
    env = {"PATH": os.environ["PATH"], "HOME": str(cwd)}
    return subprocess.run(
        [BINARY, *args], cwd=cwd, env=env, capture_output=True, text=True, check=False, timeout=300
    )


def test_positive_and_negative_cases_of_every_rule(tmp_path: Path) -> None:
    done = semgrep(
        "--test", "--config", str(SEMGREP_DIR / "rules"), str(CASES),
        *FLAGS, cwd=tmp_path,
    )  # fmt: skip
    assert done.returncode == 0, done.stdout[-2000:]
    assert "✖" not in done.stdout


@pytest.mark.parametrize("fixture", ["python-app", "js-ts-app"])
def test_fixture_expectations_are_found_and_nothing_else(tmp_path: Path, fixture: str) -> None:
    repo = ROOT / "tests/fixtures/repos" / fixture
    copy = tmp_path / "repo"  # fuori da `tests/`: Semgrep ignora quella directory
    shutil.copytree(repo, copy)
    done = semgrep(
        "--config", str(SEMGREP_DIR / "rules"), "--json", *FLAGS, ".", cwd=copy
    )  # fmt: skip
    results = json.loads(done.stdout)["results"]
    found = {
        (r["check_id"].rsplit(".", 1)[-1], r["path"], r["start"]["line"], r["end"]["line"])
        for r in results
    }
    expected = {
        (e["rule_id"], e["path"], e["start_line"], e["end_line"])
        for e in yaml.safe_load((repo / "expected-findings.yaml").read_text(encoding="utf-8"))[
            "expected"
        ]
        if "semgrep" in e["tools"]
    }
    assert found == expected

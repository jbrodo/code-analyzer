"""T-06: il valore di un segreto non esce mai da `scan` e `gate`. ADR-0011, ADR-0012, §15.

Il valore sentinella e' un segreto finto (formato di un token GitHub, marcatore `FAKE`, composto a
runtime da un seme: nel repository non esiste in forma completa) e compare in tre punti:
- nella storia git, riconosciuto da gitleaks (regola `github-pat`);
- in un'assegnazione Python `DB_PASSWORD = "<valore>"` che attiverebbe B105 (disattivata, ADR-0012);
- sulla riga trovata da una regola Semgrep del repository con una metavariabile nel messaggio
  (`message: ... $VALUE`): il testo del risultato di semgrep conterrebbe il codice trovato.

Il valore (e un suo frammento) deve mancare da report, SARIF, stdout, stderr e da ogni artefatto
scritto, con tutti e tre i formati di stdout e anche dopo `gate`. Ogni prova controlla prima che i
tre rilevatori abbiano davvero visto la riga: altrimenti l'assenza non proverebbe nulla.

`test_repository_semgrep_rule_runs_through_the_real_cli` prova il cablaggio vero di `inputs.config`;
le altre prove con la regola usano l'iniezione di `_cli_child.py`.
"""

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from .e2e_lab import REPOS, Fleet, e2e_marks

sys.path.insert(0, str(REPOS.parents[1] / "fixtures" / "builders"))
import secrets_history  # noqa: E402

pytestmark = e2e_marks
PLUGINS = ["bandit", "gitleaks", "semgrep"]
RULE_FILE = """rules:
  - id: repo-leak-probe
    languages: [python]
    severity: WARNING
    message: "assegnazione di $VALUE a $NAME"
    patterns:
      - pattern: $NAME = $VALUE
      - metavariable-regex:
          metavariable: $VALUE
          regex: '.*FAKE.*'
"""
CONFIG = "version: 1\nplugins:\n  semgrep:\n    rules: [rules/leak.yaml]\n"


class Sentinel:
    def __init__(self) -> None:
        self.value = secrets_history.fake_secrets("code-analyzer/t06/sentinel")["PAT"].value
        assert self.value.startswith("gh" + "p_") and "FAKE" in self.value
        self.needles = [self.value, self.value[8:24]]  # il valore e un suo frammento

    def leaks_in(self, text: str) -> list[str]:
        # anche la forma con escape JSON, nel caso il valore avesse caratteri speciali
        return [n for n in self.needles if n in text or json.dumps(n)[1:-1] in text]


def build_repo(root: Path, sentinel: Sentinel) -> Path:
    repo = root / "t06-repo"
    (repo / "rules").mkdir(parents=True)
    (repo / "rules" / "leak.yaml").write_text(RULE_FILE)
    (repo / ".code-analyzer.yml").write_text(CONFIG)
    env = {
        **secrets_history._git_env(root),
        "GIT_AUTHOR_NAME": "T06", "GIT_AUTHOR_EMAIL": "t06@example.invalid",
        "GIT_COMMITTER_NAME": "T06", "GIT_COMMITTER_EMAIL": "t06@example.invalid",
    }  # fmt: skip
    secrets_history.git(repo, "init", "-q", "-b", "main", env=env)
    commits = [
        ("settings.py", f'GITHUB_TOKEN = "{sentinel.value}"\n', "2026-02-01T09:00:00+00:00"),
        ("settings.py", "import os\nGITHUB_TOKEN = os.environ['T']\n", "2026-02-02T09:00:00+00:00"),
        (
            "app.py",
            "import subprocess\n"
            f'DB_PASSWORD = "{sentinel.value}"\n'
            'subprocess.run("ls", shell=True)\n',
            "2026-02-03T09:00:00+00:00",
        ),
    ]
    for name, content, date in commits:
        (repo / name).write_text(content)
        secrets_history.git(repo, "add", "-A", env=env)
        secrets_history.git(
            repo, "-c", "commit.gpgsign=false", "commit", "-q", "--no-verify", "-m", f"c {name}",
            env={**env, "GIT_AUTHOR_DATE": date, "GIT_COMMITTER_DATE": date},
        )  # fmt: skip
    return repo


@pytest.fixture(scope="module")
def sentinel() -> Sentinel:
    return Sentinel()


@pytest.fixture(scope="module")
def repo(fleet: Fleet, sentinel: Sentinel, tmp_path_factory: pytest.TempPathFactory) -> Path:
    for plugin in PLUGINS:
        fleet.add_builtin(plugin)
    return build_repo(tmp_path_factory.mktemp("t06"), sentinel)


def rules_config(tmp: Path) -> dict[str, Path]:
    path = tmp / "semgrep-config.json"
    path.write_text(json.dumps({"rules": ["rules/leak.yaml"]}))
    return {"semgrep": path}


@pytest.mark.parametrize("fmt", ["table", "json", "sarif"])
def test_sentinel_is_absent_everywhere_and_the_three_detectors_saw_the_line(
    fleet: Fleet, repo: Path, sentinel: Sentinel, tmp_path: Path, fmt: str
) -> None:
    out = tmp_path / "out"
    done = fleet.run(
        tmp_path, "scan", str(repo), "--output-dir", str(out), "--format", fmt,
        plugins=PLUGINS, inject_config=rules_config(tmp_path), out_dir=out,
    )  # fmt: skip
    assert done.returncode == 0, done.stderr[-2000:]
    report: dict[str, Any] = done.report

    # non vacuita': gitleaks (storia e HEAD), bandit (stesso file) e la regola del repository
    seen = {(f["tool"], f["rule_id"], f["location"].get("path")) for f in report["findings"]}
    assert ("gitleaks", "github-pat", "settings.py") in seen, sorted(seen)
    assert ("semgrep", "repo-leak-probe", "app.py") in seen, sorted(seen)
    assert any(t == "bandit" and p == "app.py" for t, _, p in seen), sorted(seen)
    assert not any(r == "B105" for _, r, _ in seen)  # disattivata (ADR-0012)
    assert all(p["outcome"] == "ok" for p in report["plugins"]), report["plugins"]

    leaks = sentinel.leaks_in(done.all_text())
    assert leaks == [], "il valore del segreto e' uscito (non stampato qui)"
    assert sorted(p.name for p in out.iterdir()) == [
        "code-analyzer.report.json",
        "code-analyzer.sarif",
    ]

    gate = fleet.run(tmp_path, "gate", "--report", str(out / "code-analyzer.report.json"),
                     "--fail-on", "basso,medio,alto,critico", plugins=PLUGINS)  # fmt: skip
    assert gate.returncode in (0, 1), gate.stderr
    assert sentinel.leaks_in(gate.stdout + gate.stderr) == []
    # nessun container, nessun file temporaneo con il valore nel processo di prova
    assert subprocess.run(["docker", "ps", "-aq", "--filter", "label=code-analyzer.executor=1"],
                          capture_output=True, text=True).stdout.strip() == ""  # fmt: skip


def test_gitleaks_output_keeps_the_location_but_not_the_value(
    fleet: Fleet, repo: Path, sentinel: Sentinel, tmp_path: Path
) -> None:
    """Il valore sta in due file (tre commit): un finding per file, senza valore ne' frammenti."""
    out = tmp_path / "out"
    done = fleet.run(tmp_path, "scan", str(repo), "--output-dir", str(out), "--format", "json",
                     plugins=["gitleaks"], out_dir=out)  # fmt: skip
    assert done.returncode == 0, done.stderr[-2000:]
    secrets = [f for f in done.report["findings"] if f["category"] == "secret"]
    assert sorted((f["rule_id"], f["location"]["path"]) for f in secrets) == [
        ("github-pat", "app.py"),
        ("github-pat", "settings.py"),
    ]
    assert sentinel.leaks_in(done.all_text()) == []


def test_repository_semgrep_rule_runs_through_the_real_cli(
    fleet: Fleet, repo: Path, tmp_path: Path
) -> None:
    out = tmp_path / "out"
    done = fleet.run(tmp_path, "scan", str(repo), "--output-dir", str(out), "--format", "json",
                     plugins=["semgrep"], out_dir=out)  # fmt: skip
    assert done.returncode == 0, done.stderr[-2000:]
    rules = {f["rule_id"] for f in done.report["findings"]}
    assert "repo-leak-probe" in rules

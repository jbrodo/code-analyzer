"""N-26 (S-02): le regole del repository non possono sostituire quelle integrate."""

from pathlib import Path
from typing import Any

from .e2e_lab import Fleet, copy_fixture, e2e_marks

pytestmark = e2e_marks
BUILTIN_ID = "ca-js-eval-dynamic"
OVERRIDE = f"""rules:
  - id: {BUILTIN_ID}
    languages: [javascript, typescript]
    severity: INFO
    message: mai
    pattern: nessuna_corrispondenza_possibile()
"""
CONFIG = "version: 1\nplugins:\n  semgrep:\n    rules: [rules.yaml]\n"


def scan(fleet: Fleet, work: Path, name: str, rules: str | None) -> dict[str, Any]:
    fleet.add_builtin("semgrep")
    root = copy_fixture("js-ts-app", work / name)
    if rules is not None:
        (root / "rules.yaml").write_text(rules)
        (root / ".code-analyzer.yml").write_text(CONFIG)
    done = fleet.scan(root, work / f"out-{name}", "--offline", plugins=["semgrep"])
    assert done.returncode == 0, done.stderr[-2000:]
    return done.report


def test_override_of_a_builtin_rule_fails_visibly(fleet: Fleet, work: Path) -> None:
    clean = scan(fleet, work, "n26-clean", None)
    assert any(f["rule_id"] == BUILTIN_ID for f in clean["findings"])  # il vettore e' attivo
    report = scan(fleet, work, "n26-override", OVERRIDE)
    assert report["status"] == "partial"
    assert [p["outcome"] for p in report["plugins"]] == ["failed"]


def test_additional_rules_leave_the_builtin_results(fleet: Fleet, work: Path) -> None:
    report = scan(fleet, work, "n26-extra", OVERRIDE.replace(BUILTIN_ID, "repo-extra"))
    assert report["status"] == "complete"
    assert any(f["rule_id"] == BUILTIN_ID for f in report["findings"])

"""T-07: matrice E2E di `scan` e `gate` con il plugin finto firmato (T-02). ADR-0005, 0009, 0010.

Processi veri (`_cli_child.py`), immagine del plugin finto costruita, spinta su un registry locale
e firmata con `sign-local.sh`. Il comportamento del plugin finto si sceglie con `inputs.config`,
che `run_plugins` non cabla: lo inietta il processo figlio (vedi `test_scan_e2e.py`, L-04).

Exit atteso: 0 superato, 1 fallito, 2 errore (scansione parziale senza `--allow-partial`, firma
assente o errata, report illeggibile, argomenti non validi). `scan` esce sempre 0 o 2, mai 1.

Il plugin finto emette `uri: /workspace/app.py` con `uriBaseId`, che K-05 rifiuta (ADR-0007):
come in `test_scan_e2e.py` si usa una copia di prova col solo `uri` corretto; il fixture
originale non si tocca.
"""

import json
import shutil
from datetime import date, timedelta
from pathlib import Path

import pytest

from .e2e_lab import ROOT, CliResult, Fleet, e2e_marks

pytestmark = e2e_marks
FAKE = ROOT / "tests/fixtures/plugins/fake"
PLUGINS = ["fake-plugin"]
LEVEL = (
    "medio"  # livello provvisorio del finding del plugin finto (SARIF `warning`), verificato sotto
)


@pytest.fixture(scope="module")
def fake(fleet: Fleet, tmp_path_factory: pytest.TempPathFactory) -> Fleet:
    context = tmp_path_factory.mktemp("t07-ctx") / "context"
    shutil.copytree(FAKE, context, ignore=shutil.ignore_patterns("__pycache__", "test_*"))
    script = context / "fake_plugin.py"
    source = script.read_text()
    patched = source.replace('"/workspace/app.py"', '"app.py"').replace(
        '                                "uriBaseId": "%SRCROOT%",\n', ""
    )
    assert patched != source and patched.count("uriBaseId") == source.count("uriBaseId") - 1
    script.write_text(patched)
    data = json.loads((FAKE / "plugin.yaml").read_text())
    data["categories"] = ["sast"]  # `quality` non ha ancora un kind in Fase 1 (K-05)
    fleet.add("fake-plugin", context, data, gate_image=False)
    return fleet


class Case:
    """Una scansione con un comportamento e una configurazione; ogni test ne ottiene una nuova."""

    def __init__(self, fleet: Fleet, tmp: Path) -> None:
        self.fleet, self.tmp = fleet, tmp
        self.repo = tmp / "repo"
        self.repo.mkdir()
        (self.repo / "app.py").write_text("print(1)\n")
        self.out = tmp / "out"

    def scan(
        self,
        behavior: str = "success",
        *,
        config: str | None = None,
        key: Path | None = None,
        env: dict[str, str] | None = None,
        extra: tuple[str, ...] = (),
    ) -> CliResult:
        if config is not None:
            (self.repo / ".code-analyzer.yml").write_text(config)
        behavior_file = self.tmp / "behavior.json"
        behavior_file.write_text(json.dumps({"behavior": behavior}))
        return self.fleet.run(
            self.tmp, "scan", str(self.repo), "--output-dir", str(self.out), "--format", "json",
            *extra, plugins=PLUGINS, inject_config={"fake-plugin": behavior_file}, key=key,
            env=env, out_dir=self.out,
        )  # fmt: skip

    def gate(self, *args: str) -> CliResult:
        return self.fleet.run(self.tmp, "gate", "--report",
                              str(self.out / "code-analyzer.report.json"), *args,
                              plugins=PLUGINS)  # fmt: skip


@pytest.fixture
def case(fake: Fleet, tmp_path: Path) -> Case:
    return Case(fake, tmp_path)


def test_baseline_complete_scan_has_one_finding_of_the_expected_level(case: Case) -> None:
    done = case.scan()
    assert done.returncode == 0, done.stderr
    report = done.report
    assert report["status"] == "complete"
    (finding,) = report["findings"]
    assert (finding["rule_id"], finding["level"]) == ("fake.rule", LEVEL)
    (run,) = report["plugins"]
    assert (run["outcome"], run["signature"]) == ("ok", "verified")


@pytest.mark.parametrize(
    ("args", "code", "verdict"),
    [
        ((), 0, "superato"),  # soglia predefinita critico+alto: il finding e' `medio`
        (("--fail-on", LEVEL), 1, "fallito"),
        (("--fail-on", "critico,alto"), 0, "superato"),
        (("--fail-on", "basso,medio,alto,critico"), 1, "fallito"),
        (("--fail-on", ""), 0, "superato"),  # scelta esplicita: nulla blocca
    ],
    ids=["default", "fail-on-hit", "fail-on-miss", "fail-on-all", "fail-on-empty"],
)
def test_gate_exit_on_a_complete_scan(
    case: Case, args: tuple[str, ...], code: int, verdict: str
) -> None:
    assert case.scan().returncode == 0
    done = case.gate(*args)
    assert done.returncode == code, done.stderr
    assert done.stdout.startswith(f"gate: {verdict}")
    assert ("bloccante" in done.stdout) == (code == 1)


def test_gate_rejects_an_unknown_level_with_exit_2(case: Case) -> None:
    assert case.scan().returncode == 0
    done = case.gate("--fail-on", "gravissimo")
    assert done.returncode == 2 and "Traceback" not in done.stderr


@pytest.mark.parametrize(
    "behavior", ["exit-nonzero", "invalid-sarif", "oversize", "symlink-out", "timeout"]
)
def test_failed_plugin_gives_a_partial_report_and_gate_exits_2(case: Case, behavior: str) -> None:
    done = case.scan(behavior)
    assert done.returncode == 0, done.stderr  # scan non decide
    report = done.report
    assert report["status"] == "partial"
    (run,) = report["plugins"]
    assert run["outcome"] == "failed" and run["failure"]
    assert case.gate().returncode == 2
    assert case.gate("--fail-on", "").returncode == 2


def test_partial_scan_with_allow_partial_is_evaluated_not_ignored(case: Case) -> None:
    """`--allow-partial` valuta cio' che c'e': il fallimento del plugin e' un finding `health`."""
    assert case.scan("exit-nonzero").returncode == 0
    report = json.loads((case.out / "code-analyzer.report.json").read_text())
    health = [f for f in report["findings"] if f["category"] == "health"]
    assert [f["rule_id"] for f in health] == ["ca.scanner-not-run"]
    allowed = case.gate("--allow-partial")
    assert allowed.returncode in (0, 1), allowed.stderr
    assert "partial-scan" in allowed.stderr
    on_health = case.gate("--allow-partial", "--fail-on", health[0]["level"])
    assert on_health.returncode == 1
    assert "motivo: partial-scan" in on_health.stderr


def test_wrong_key_exits_2_without_report_and_without_container(case: Case) -> None:
    done = case.scan(key=case.fleet.other_public_key)
    assert done.returncode == 2
    assert not case.out.exists() and "Traceback" not in done.stderr
    assert case.gate().returncode == 2  # nessun report da leggere


def test_missing_public_key_exits_2_without_report(case: Case, tmp_path: Path) -> None:
    done = case.scan(key=tmp_path / "does-not-exist.pub")
    assert done.returncode == 2 and not case.out.exists()


def test_unsigned_development_mode_is_skipped_and_the_gate_refuses_it(case: Case) -> None:
    done = case.scan(env={"CA_INSECURE_ALLOW_UNSIGNED": "1"})
    assert done.returncode == 0, done.stderr
    (run,) = done.report["plugins"]
    assert run["signature"] == "skipped"
    refused = case.gate("--fail-on", "")
    assert refused.returncode == 2 and "signature-skipped" in refused.stderr
    allowed = case.gate("--fail-on", "", "--allow-partial")  # ADR-0005: solo con --allow-partial
    assert allowed.returncode == 0


def test_new_findings_only_is_treated_as_all_with_a_warning(case: Case) -> None:
    config = f"version: 1\ngate:\n  mode: new-findings-only\n  block_on: [{LEVEL}]\n"
    done = case.scan(config=config)
    assert done.returncode == 0, done.stderr
    report = done.report
    assert report["gate"]["mode"] == "new-findings-only"
    assert report["gate"]["effective_mode"] == "all"
    assert "new-findings-only-as-all" in {w["code"] for w in report["warnings"]}
    assert "equivale a 'all'" in done.stderr
    assert case.gate().returncode == 1  # blocca come con `all`: il finding c'e' ed e' bloccante


def exception_config(fingerprint: str, expires: date) -> str:
    return (
        f"version: 1\ngate:\n  block_on: [{LEVEL}]\n"
        f"exceptions:\n  - fingerprint: '{fingerprint}'\n    reason: prova T-07\n"
        f"    expires: {expires.isoformat()}\n    approved_by: test\n"
    )


def test_active_exception_accepts_the_finding_and_the_gate_passes(case: Case) -> None:
    first = case.scan(config=f"version: 1\ngate:\n  block_on: [{LEVEL}]\n")
    (finding,) = first.report["findings"]
    assert case.gate().returncode == 1
    done = case.scan(config=exception_config(finding["fingerprint"], date.today() + timedelta(30)))
    assert done.returncode == 0, done.stderr
    (accepted,) = done.report["findings"]
    assert accepted["status"] == "accettato"
    assert [e["fingerprint"] for e in done.report["exceptions"]] == [finding["fingerprint"]]
    assert case.gate().returncode == 0


def test_expired_exception_is_ignored_with_a_warning_and_the_gate_fails(case: Case) -> None:
    first = case.scan(config=f"version: 1\ngate:\n  block_on: [{LEVEL}]\n")
    (finding,) = first.report["findings"]
    expired = exception_config(finding["fingerprint"], date.today() - timedelta(1))
    done = case.scan(config=expired)
    assert done.returncode == 0, done.stderr
    (still_open,) = done.report["findings"]
    assert still_open["status"] == "aperto"
    assert done.report["exceptions"] == []
    assert "scaduta" in done.stderr
    assert case.gate().returncode == 1


def test_gate_reads_nothing_but_the_report(case: Case, tmp_path: Path) -> None:
    broken = tmp_path / "broken.json"
    broken.write_text("{not json")
    assert (
        case.fleet.run(tmp_path, "gate", "--report", str(broken), plugins=PLUGINS).returncode == 2
    )
    assert case.fleet.run(tmp_path, "gate", "--report", str(tmp_path / "none.json"),
                          plugins=PLUGINS).returncode == 2  # fmt: skip


def test_scan_never_exits_1_and_leaves_exactly_two_artifacts(case: Case) -> None:
    done = case.scan(config=f"version: 1\ngate:\n  block_on: [{LEVEL}]\n")
    assert done.returncode == 0
    assert sorted(p.name for p in case.out.iterdir()) == [
        "code-analyzer.report.json",
        "code-analyzer.sarif",
    ]


def test_stdout_json_is_the_same_document_as_the_report_file(case: Case) -> None:
    done = case.scan()
    assert json.loads(done.stdout) == done.report

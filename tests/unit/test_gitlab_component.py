"""N-07: il componente GitLab. Senza istanza GitLab: struttura e script con `docker` finto."""

import os
import re
import stat
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2] / "integrations" / "gitlab-component"
TEXT = (ROOT / "templates" / "code-analyzer.yml").read_text()
SPEC, JOB = list(yaml.safe_load_all(TEXT))
JOB = JOB["code-analyzer"]
SCRIPT = JOB["script"][0]


def test_image_and_key_are_inputs_without_defaults() -> None:
    inputs = SPEC["spec"]["inputs"]
    for name in ("image", "public_key"):
        assert "default" not in inputs[name]


def test_job_image_is_pinned_by_digest() -> None:
    assert re.search(r"@sha256:[0-9a-f]{64}$", SPEC["spec"]["inputs"]["job_image"]["default"])


def test_scan_never_gets_fail_on_and_the_gate_is_the_last_command() -> None:
    assert "--fail-on" not in "".join(
        line for line in SCRIPT.splitlines() if " scan" in line or "ca scan" in line
    )
    last = [line for line in SCRIPT.splitlines() if line.strip()][-1]
    assert "ca gate" in last


def test_all_four_native_reports_are_declared_and_kept_even_after_a_failure() -> None:
    artifacts = JOB["artifacts"]
    assert artifacts["when"] == "always"
    assert set(artifacts["reports"]) == {"sast", "dependency_scanning", "codequality", "cyclonedx"}


def test_the_daemon_is_checked_first() -> None:
    lines = [line.strip() for line in SCRIPT.splitlines() if line.strip()]
    assert any("docker info" in line for line in lines[:4])


def test_no_token_and_no_merge_request_comment() -> None:
    assert "CI_JOB_TOKEN" not in TEXT and "notes" not in TEXT


# --- script con `docker` finto -------------------------------------------------------------


@pytest.fixture
def sandbox(tmp_path: Path) -> dict[str, Any]:
    repo = tmp_path / "project"
    repo.mkdir()
    git = ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-C", str(repo)]
    subprocess.run([*git, "init", "-q", "-b", "main"], check=True)
    (repo / "f.txt").write_text("base\n")
    subprocess.run([*git, "add", "."], check=True)
    subprocess.run([*git, "commit", "-q", "-m", "base"], check=True)
    base = subprocess.run(
        [*git, "rev-parse", "HEAD"], check=True, capture_output=True, text=True
    ).stdout.strip()
    (repo / "f.txt").write_text("head\n")
    subprocess.run([*git, "commit", "-qam", "head"], check=True)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "chown").write_text("#!/bin/sh\nexit 0\n")
    (bin_dir / "docker").write_text(
        """#!/bin/sh
[ "$1" = info ] && exit "${FAKE_DOCKER_INFO:-0}"
echo "$*" >> "$FAKE_LOG"
out=""
for a in "$@"; do case "$a" in *:/ca/output) out="${a%:/ca/output}";; esac; done
for a in "$@"; do mode="$a"; done
set -- $(echo "$*")
while [ $# -gt 0 ]; do
  case "$1" in scan|sbom|export|gate) mode="$1"; break;; esac; shift
done
case "$mode" in
  scan) echo '{}' > "$out/code-analyzer.report.json"; echo '{}' > "$out/code-analyzer.sarif";;
  sbom) echo '{}' > "$out/sbom.cdx.json";;
  export)
    for n in gl-sast-report.json gl-dependency-scanning-report.json \\
      gl-code-quality-report.json; do echo '{}' > "$out/$n"; done;;
  gate) exit "${FAKE_GATE_EXIT:-0}";;
esac
"""
    )
    for name in ("chown", "docker"):
        path = bin_dir / name
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
    key = tmp_path / "cosign.pub"
    key.write_text("key")
    env = {
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "HOME": str(tmp_path),
        "FAKE_LOG": str(tmp_path / "docker.log"),
        "CI_PROJECT_DIR": str(repo),
        "CI_BUILDS_DIR": str(tmp_path / "builds"),
        "CI_JOB_ID": "7",
        "CA_IMAGE": "registry.example/ca-cli:1",
        "CA_PUBLIC_KEY": str(key),
        "CA_FAIL_ON": "",
        "CA_SBOM": "true",
        "CA_OFFLINE": "false",
        "CA_NETWORK": "",
    }
    (tmp_path / "builds").mkdir()
    return {"env": env, "repo": repo, "base": base, "log": tmp_path / "docker.log"}


def run_script(sandbox: dict[str, Any], **extra: str) -> subprocess.CompletedProcess[str]:
    env = {**sandbox["env"], **extra}
    return subprocess.run(
        ["sh", "-c", SCRIPT],
        env=env,
        capture_output=True,
        text=True,
        check=False,
        cwd=sandbox["repo"],
    )


def calls(sandbox: dict[str, Any]) -> list[str]:
    return sandbox["log"].read_text().splitlines()


def mr(sandbox: dict[str, Any]) -> dict[str, str]:
    return {
        "CI_PIPELINE_SOURCE": "merge_request_event",
        "CI_MERGE_REQUEST_DIFF_BASE_SHA": sandbox["base"],
        "CI_MERGE_REQUEST_IID": "9",
    }


def test_branch_pipeline_scans_exports_and_gates_in_order(sandbox: dict[str, Any]) -> None:
    result = run_script(sandbox, CI_PIPELINE_SOURCE="push")
    assert result.returncode == 0, result.stderr
    modes = [
        next(w for w in c.split() if w in ("scan", "sbom", "export", "gate"))
        for c in calls(sandbox)
    ]
    assert modes == ["scan", "sbom", "export", "gate"]
    assert "--pr" not in " ".join(calls(sandbox))
    for name in ("code-analyzer.report.json", "code-analyzer.sarif", "gl-sast-report.json"):
        assert (sandbox["repo"] / name).is_file(), name


def test_merge_request_scans_the_base_first_and_passes_the_baseline(
    sandbox: dict[str, Any],
) -> None:
    result = run_script(sandbox, **mr(sandbox))
    assert result.returncode == 0, result.stderr
    scans = [c for c in calls(sandbox) if " scan" in c]
    assert len(scans) == 2 and "--pr" not in scans[0]
    assert "--pr" in scans[1] and f"--base {sandbox['base']}" in scans[1]
    assert "--baseline /ca/output/baseline/code-analyzer.report.json" in scans[1]
    assert "--pull-request 9" in scans[1] and "--baseline-source base-scan" in scans[1]
    assert not any("--fail-on" in c for c in scans)


def test_the_job_fails_with_the_exit_of_the_gate_after_the_artifacts_are_kept(
    sandbox: dict[str, Any],
) -> None:
    result = run_script(sandbox, CI_PIPELINE_SOURCE="push", FAKE_GATE_EXIT="1")
    assert result.returncode == 1
    assert (sandbox["repo"] / "gl-sast-report.json").is_file()


def test_fail_on_goes_to_the_gate_only(sandbox: dict[str, Any]) -> None:
    run_script(sandbox, CI_PIPELINE_SOURCE="push", CA_FAIL_ON="critico,alto")
    gate = [c for c in calls(sandbox) if c.endswith("gate --fail-on critico,alto")]
    assert len(gate) == 1
    assert not any("--fail-on" in c for c in calls(sandbox) if " scan" in c)


def test_without_a_daemon_it_stops_with_a_clear_message(sandbox: dict[str, Any]) -> None:
    result = run_script(sandbox, CI_PIPELINE_SOURCE="push", FAKE_DOCKER_INFO="1")
    assert result.returncode == 2 and "daemon" in result.stderr
    assert not sandbox["log"].exists()


def test_a_base_commit_missing_from_the_history_is_an_error(sandbox: dict[str, Any]) -> None:
    result = run_script(sandbox, **{**mr(sandbox), "CI_MERGE_REQUEST_DIFF_BASE_SHA": "a" * 40})
    assert result.returncode == 2 and "git_depth" in result.stderr


def test_hostile_base_sha_is_refused_before_any_use(sandbox: dict[str, Any]) -> None:
    result = run_script(sandbox, **{**mr(sandbox), "CI_MERGE_REQUEST_DIFF_BASE_SHA": "x; id"})
    assert result.returncode == 2
    assert not sandbox["log"].exists()


def test_a_failed_scan_still_exports_nothing_and_fails(sandbox: dict[str, Any]) -> None:
    """Senza report non si esporta e il job fallisce con l'exit della scansione."""
    bad = Path(sandbox["env"]["PATH"].split(":")[0]) / "docker"
    bad.write_text('#!/bin/sh\n[ "$1" = info ] && exit 0\necho "$*" >> "$FAKE_LOG"\nexit 2\n')
    result = run_script(sandbox, CI_PIPELINE_SOURCE="push")
    assert result.returncode == 2
    assert not (sandbox["repo"] / "gl-sast-report.json").exists()

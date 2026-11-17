"""N-04: l'Action composita e i suoi script, con `docker` e `gh` finti (niente rete né Docker)."""

import json
import os
import re
import stat
import subprocess
import zipfile
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2] / "integrations" / "github-action"
ACTION = yaml.safe_load((ROOT / "action.yml").read_text())
STEPS = ACTION["runs"]["steps"]
SHA40 = "a" * 40


def step(name: str) -> dict:
    return next(s for s in STEPS if s["name"] == name)


def commands(s: dict) -> str:
    return s.get("run", "")


# --- struttura -------------------------------------------------------------------------------


def test_action_is_composite_and_has_no_default_image() -> None:
    assert ACTION["runs"]["using"] == "composite"
    assert ACTION["inputs"]["image"]["required"] is True
    assert "default" not in ACTION["inputs"]["image"]
    assert "default" not in ACTION["inputs"]["public-key"]


def test_event_guard_refuses_pull_request_target_and_comes_first() -> None:
    assert STEPS[0]["name"] == "Controlla l'evento"
    assert "pull_request_target" in commands(STEPS[0])
    assert "exit 2" in commands(STEPS[0])


def test_steps_follow_the_order_of_the_adr() -> None:
    order = [s["name"] for s in STEPS]
    names = ["Scan", "Carica il SARIF", "Notify", "Gate"]
    assert [order.index(n) for n in names] == sorted(order.index(n) for n in names)
    assert order[-1] == "Gate"


def test_scan_never_receives_fail_on_and_gate_does() -> None:
    assert "--fail-on" not in commands(step("Scan"))
    assert "--fail-on" in commands(step("Gate"))


def test_sarif_upload_runs_even_after_a_failure() -> None:
    assert "always()" in step("Carica il SARIF")["if"]


def test_notify_only_on_pull_requests_and_does_not_decide() -> None:
    notify = step("Notify")
    assert "pull_request" in notify["if"]
    assert "gate" not in commands(notify)


def test_third_party_actions_are_pinned_by_commit_hash() -> None:
    uses = [s["uses"] for s in STEPS if "uses" in s]
    assert uses, "attesi passi con uses"
    for ref in uses:
        assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", ref), ref


def test_expressions_never_reach_the_shell_directly() -> None:
    """Un'espressione `${{ }}` dentro `run:` sarebbe un'iniezione: i valori passano per `env:`."""
    for s in STEPS:
        assert "${{" not in commands(s), s["name"]


def test_token_reaches_only_the_steps_that_need_it() -> None:
    holders = {
        s["name"]
        for s in STEPS
        if any("github-token" in str(v) for v in (s.get("env") or {}).values())
    }
    assert holders == {"Cerca la baseline tra gli artefatti", "Carica il SARIF", "Notify"}


def test_baseline_artifact_is_stored_only_for_pushes_to_the_default_branch() -> None:
    store = step("Conserva il report del branch principale")
    assert "github.event_name == 'push'" in store["if"]
    assert "default_branch" in store["if"]
    assert store["with"]["name"] == "code-analyzer-baseline"


def test_action_does_not_use_the_ci_cache_for_the_baseline() -> None:
    assert not any("cache" in s.get("uses", "") for s in STEPS)


# --- script ----------------------------------------------------------------------------------


@pytest.fixture
def fake_bin(tmp_path: Path) -> Path:
    """`docker` registra gli argomenti; `gh` risponde dalla cartella `gh/`; `stat` è quello vero."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    docker = bin_dir / "docker"
    docker.write_text(
        '#!/usr/bin/env bash\nprintf "%s\\n" "$@" > "$FAKE_LOG"\n'
        'env | grep -E "^(GITHUB_TOKEN|CA_)" >> "$FAKE_ENV" || true\n'
    )
    docker.chmod(docker.stat().st_mode | stat.S_IXUSR)
    return bin_dir


def env_for(tmp_path: Path, fake_bin: Path, **extra: str) -> dict[str, str]:
    env = {
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "HOME": str(tmp_path),
        "FAKE_LOG": str(tmp_path / "docker.log"),
        "FAKE_ENV": str(tmp_path / "docker.env"),
        "CA_IMAGE": "registry.example/ca-cli:1",
        "CA_WORKSPACE": str(tmp_path / "ws"),
        "CA_WORK": str(tmp_path / "work"),
        "CA_CACHE": str(tmp_path / "cache"),
        "CA_OUTPUT": str(tmp_path / "out"),
        "CA_PUBLIC_KEY": str(tmp_path / "cosign.pub"),
    }
    env.update(extra)
    return env


def run(
    script: str, tmp_path: Path, env: dict[str, str], *args: str
) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", str(ROOT / script), *args], env=env, capture_output=True, text=True, check=False
    )


def logged(tmp_path: Path) -> list[str]:
    return (tmp_path / "docker.log").read_text().splitlines()


def test_run_cli_scan_mounts_the_socket_and_passes_no_token(tmp_path: Path, fake_bin: Path) -> None:
    env = env_for(tmp_path, fake_bin, GITHUB_TOKEN="ghs_secret")
    result = run("run-cli.sh", tmp_path, env, "scan", "--output-dir", "/ca/output")
    assert result.returncode == 0, result.stderr
    args = logged(tmp_path)
    assert any(a.startswith("/var/run/docker.sock:") for a in args)
    assert "--privileged" not in args
    assert "ghs_secret" not in "\n".join(args)
    assert "GITHUB_TOKEN" not in args
    assert args[-3:] == ["scan", "--output-dir", "/ca/output"]


def test_run_cli_gate_and_notify_do_not_mount_the_socket(tmp_path: Path, fake_bin: Path) -> None:
    event = tmp_path / "event.json"
    event.write_text("{}")
    env = env_for(tmp_path, fake_bin, GITHUB_TOKEN="ghs_secret", GITHUB_EVENT_PATH=str(event))
    for mode in ("gate", "notify"):
        assert run("run-cli.sh", tmp_path, env, mode).returncode == 0
        assert not any("docker.sock" in a for a in logged(tmp_path)), mode


def test_run_cli_gives_the_token_to_notify_by_name_only(tmp_path: Path, fake_bin: Path) -> None:
    event = tmp_path / "event.json"
    event.write_text("{}")
    env = env_for(tmp_path, fake_bin, GITHUB_TOKEN="ghs_secret", GITHUB_EVENT_PATH=str(event))
    assert run("run-cli.sh", tmp_path, env, "notify").returncode == 0
    args = logged(tmp_path)
    assert "GITHUB_TOKEN" in args
    assert "ghs_secret" not in "\n".join(args)


def test_run_cli_hardens_the_container(tmp_path: Path, fake_bin: Path) -> None:
    env = env_for(tmp_path, fake_bin)
    assert run("run-cli.sh", tmp_path, env, "gate").returncode == 0
    args = logged(tmp_path)
    for flag in ("--cap-drop", "ALL", "--read-only", "no-new-privileges"):
        assert flag in args
    assert f"{tmp_path / 'ws'}:/ca/workspace:ro" in args


def test_run_cli_network_only_when_asked(tmp_path: Path, fake_bin: Path) -> None:
    assert run("run-cli.sh", tmp_path, env_for(tmp_path, fake_bin), "gate").returncode == 0
    assert "--network" not in logged(tmp_path)
    env = env_for(tmp_path, fake_bin, CA_NETWORK="host")
    assert run("run-cli.sh", tmp_path, env, "gate").returncode == 0
    assert "host" in logged(tmp_path)


def test_run_cli_rejects_unknown_commands_and_missing_variables(
    tmp_path: Path, fake_bin: Path
) -> None:
    assert run("run-cli.sh", tmp_path, env_for(tmp_path, fake_bin), "upload").returncode == 2
    env = env_for(tmp_path, fake_bin)
    del env["CA_IMAGE"]
    assert run("run-cli.sh", tmp_path, env, "gate").returncode == 2


def _fake_gh(fake_bin: Path, tmp_path: Path, answers: dict[str, str]) -> None:
    """`gh api <percorso>`: risponde con il file che corrisponde alla parte finale del percorso."""
    table = tmp_path / "gh-answers.json"
    table.write_text(json.dumps(answers))
    gh = fake_bin / "gh"
    gh.write_text(
        "#!/usr/bin/env bash\n"
        "python3 -I - \"$@\" <<'PY'\n"
        "import json, sys, pathlib\n"
        f"answers = json.load(open({str(table)!r}))\n"
        "path = sys.argv[2]\n"
        "for key, value in answers.items():\n"
        "    if key in path:\n"
        "        if value.startswith('@'):\n"
        "            sys.stdout.buffer.write(pathlib.Path(value[1:]).read_bytes())\n"
        "        elif value == '!':\n"
        "            sys.exit(1)\n"
        "        else:\n"
        "            print(value)\n"
        "        sys.exit(0)\n"
        "sys.exit(1)\n"
        "PY\n"
    )
    gh.chmod(gh.stat().st_mode | stat.S_IXUSR)


def baseline_env(tmp_path: Path, fake_bin: Path, **extra: str) -> dict[str, str]:
    out = tmp_path / "gh-output"
    return {
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "GH_TOKEN": "t",
        "GITHUB_REPOSITORY": "owner/repo",
        "GITHUB_WORKFLOW_REF": "owner/repo/.github/workflows/ci.yml@refs/pull/3/merge",
        "BASE_SHA": SHA40,
        "DEFAULT_BRANCH": "main",
        "CA_BASELINE_DIR": str(tmp_path / "baseline"),
        "GITHUB_OUTPUT": str(out),
        **extra,
    }


def test_fetch_baseline_extracts_only_the_report(tmp_path: Path, fake_bin: Path) -> None:
    archive = tmp_path / "artifact.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("code-analyzer.report.json", '{"ok": true}')
        z.writestr("../evil", "x")
    _fake_gh(
        fake_bin,
        tmp_path,
        {"/zip": f"@{archive}", "/artifacts": "77 1000", "/runs": "42"},
    )
    result = run("fetch-baseline.sh", tmp_path, baseline_env(tmp_path, fake_bin))
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "gh-output").read_text() == "found=true\n"
    assert (tmp_path / "baseline" / "code-analyzer.report.json").read_text() == '{"ok": true}'
    assert not (tmp_path / "evil").exists()
    assert [p.name for p in (tmp_path / "baseline").iterdir()] == ["code-analyzer.report.json"]


@pytest.mark.parametrize(
    "answers",
    [
        {"/runs": ""},  # nessuna esecuzione sul commit base
        {"/runs": "!"},  # la ricerca fallisce
        {"/runs": "42", "/artifacts": "null null"},  # artefatto assente o scaduto
        {"/runs": "42", "/artifacts": f"7 {200 * 1024 * 1024}"},  # troppo grande
    ],
)
def test_fetch_baseline_reports_not_found_without_failing(
    tmp_path: Path, fake_bin: Path, answers: dict[str, str]
) -> None:
    _fake_gh(fake_bin, tmp_path, answers)
    result = run("fetch-baseline.sh", tmp_path, baseline_env(tmp_path, fake_bin))
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "gh-output").read_text() == "found=false\n"


def test_fetch_baseline_rejects_hostile_inputs(tmp_path: Path, fake_bin: Path) -> None:
    _fake_gh(fake_bin, tmp_path, {})
    for key, value in [("BASE_SHA", "abc; rm -rf /"), ("GITHUB_REPOSITORY", "a/b/../c")]:
        env = baseline_env(tmp_path, fake_bin, **{key: value})
        assert run("fetch-baseline.sh", tmp_path, env, "").returncode == 2, key
    env = baseline_env(tmp_path, fake_bin, GITHUB_WORKFLOW_REF="o/r/.github/workflows/$(id).yml@x")
    result = run("fetch-baseline.sh", tmp_path, env)
    assert result.returncode == 0
    assert (tmp_path / "gh-output").read_text() == "found=false\n"


def test_scan_base_checks_out_the_base_in_a_separate_clone(tmp_path: Path, fake_bin: Path) -> None:
    repo = tmp_path / "ws"
    repo.mkdir()
    git = ["git", "-c", "user.name=t", "-c", "user.email=t@e.x", "-C", str(repo)]
    subprocess.run([*git, "init", "-q", "-b", "main"], check=True)
    (repo / "f.txt").write_text("base\n")
    subprocess.run([*git, "add", "."], check=True)
    subprocess.run([*git, "commit", "-q", "-m", "base"], check=True)
    base = subprocess.run(
        [*git, "rev-parse", "HEAD"], check=True, capture_output=True, text=True
    ).stdout.strip()
    (repo / "f.txt").write_text("head\n")
    subprocess.run([*git, "commit", "-qam", "head"], check=True)

    root = tmp_path / "root"
    root.mkdir()
    # il `docker` finto non scrive il report: lo scrive questo wrapper al posto della CLI
    docker = fake_bin / "docker"
    docker.write_text(
        '#!/usr/bin/env bash\nprintf "%s\\n" "$@" > "$FAKE_LOG"\n'
        'for a in "$@"; do case "$a" in *:/ca/output) d="${a%:/ca/output}";; esac; done\n'
        'echo \'{"base": true}\' > "$d/code-analyzer.report.json"\n'
    )
    env = env_for(tmp_path, fake_bin, BASE_SHA=base, CA_BASELINE_DIR=str(tmp_path / "baseline"))
    env["CA_SCAN_ROOT"] = str(root)
    result = run("scan-base.sh", tmp_path, env)
    assert result.returncode == 0, result.stderr
    assert (root / "base" / "f.txt").read_text() == "base\n"
    assert (tmp_path / "baseline" / "code-analyzer.report.json").exists()
    args = logged(tmp_path)
    assert f"{root / 'base'}:/ca/workspace:ro" in args
    assert "--pr" not in args and "--baseline" not in args
    assert oct((root / "base-output").stat().st_mode & 0o777) == "0o700"

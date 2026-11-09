"""Plugin gitleaks (P-07) senza Docker: manifest, adattatore, git ombra, fixture, Dockerfile.

Le prove su immagine reale sono in `tests/integration/test_gitleaks_image.py` e
`tests/integration/test_gitleaks_hostile_repo.py`. L'output registrato in `fixtures/output/` e'
letto anche dal test di contratto T-04 (`tests/contract/plugins`), con il controllo K-10.
"""

import hashlib
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml
from jsonschema import Draft202012Validator

from ca_core.models import PluginManifest

ROOT = Path(__file__).resolve().parents[2]
GITLEAKS = ROOT / "packages/ca-plugins/src/ca_plugins/builtin/gitleaks"
OUTPUTS = sorted((GITLEAKS / "fixtures/output").glob("gitleaks.*.sarif"))
TARBALL_SHA256 = "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"  # V-01

_spec = importlib.util.spec_from_file_location("gitleaks_adapter", GITLEAKS / "gitleaks_adapter.py")
assert _spec and _spec.loader
adapter = importlib.util.module_from_spec(_spec)
sys.modules["gitleaks_adapter"] = adapter
_spec.loader.exec_module(adapter)

MANIFEST: dict[str, Any] = yaml.safe_load((GITLEAKS / "plugin.yaml").read_text())
SECRET = "sentinel-secret-value-9f3a"
SHA = "a" * 40


def raw_result(**changes: Any) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": "github-pat",
        "message": {"text": f"github-pat has detected secret for file app/s.py at commit {SHA}."},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "app/s.py"},
                    "region": {
                        "startLine": 3,
                        "startColumn": 1,
                        "endLine": 3,
                        "endColumn": 9,
                        "snippet": {"text": SECRET},
                    },
                }
            }
        ],
        "partialFingerprints": {
            "commitSha": SHA,
            "email": "someone@example.invalid",
            "author": "Some One",
            "date": "2026-01-05T09:00:00Z",
            "commitMessage": "add the sentinel",
        },
        "properties": {"tags": []},
    }
    return {**result, **changes}


def raw_sarif(*results: dict[str, Any]) -> bytes:
    run = {"tool": {"driver": {"name": "gitleaks"}}, "results": list(results)}
    return json.dumps({"version": "2.1.0", "runs": [run]}).encode()


# --- manifest ---------------------------------------------------------------------------


def test_manifest_valid_for_schema_and_model() -> None:
    schema = json.loads((ROOT / "schemas" / "plugin-manifest.schema.json").read_text())
    Draft202012Validator(schema).validate(MANIFEST)
    model = PluginManifest.model_validate(MANIFEST)
    assert (model.name, model.network, model.inputs.config) == ("gitleaks", "none", "none")
    assert model.outputs.sarif == "/out/results.sarif" and model.languages == []
    assert [c.value for c in model.categories] == ["secret"]


def test_manifest_has_no_real_registry_and_no_digest() -> None:
    image = MANIFEST["image"]
    assert image.startswith("registry.invalid/") and "@" not in image  # D-0005 aperta
    assert not image.endswith(":latest")


def test_manifest_limits_are_documented_and_cover_the_measurements() -> None:
    text = (GITLEAKS / "plugin.yaml").read_text()
    assert "X-02" in text and "saleor" in text and "80 s" in text
    assert MANIFEST["outputs"]["max_bytes"] >= 100 * 37_916  # massimo misurato (saleor)
    res = MANIFEST["resources"]
    assert (res["cpu"], res["memory"], res["timeout"], res["pids"]) == ("1", "1Gi", "300s", 128)


# --- fixture registrate ---------------------------------------------------------------------


def test_recorded_outputs_cover_the_history_fixture_and_the_two_plain_ones() -> None:
    assert [p.name for p in OUTPUTS] == [
        "gitleaks.js-ts-app.sarif",
        "gitleaks.python-app.sarif",
        "gitleaks.secrets-history.sarif",
    ]


@pytest.mark.parametrize("path", OUTPUTS, ids=lambda p: p.name)
def test_recorded_outputs_are_redacted_and_have_no_local_paths(path: Path) -> None:
    text = path.read_text()
    assert "/workspace" not in text and "/home/" not in text and "/tmp/" not in text
    for forbidden in ("snippet", "email", "author", "commitMessage", "REDACTED", "ghp_", "glpat-"):
        assert forbidden not in text
    for result in json.loads(text)["runs"][0]["results"]:
        assert set(result["properties"]) == {"secret_sha256"}
        assert re.fullmatch(r"[0-9a-f]{64}", result["properties"]["secret_sha256"])


# --- adattatore: SARIF -------------------------------------------------------------------------


def test_adapt_redacts_and_hashes_the_value() -> None:
    out = adapter.adapt(raw_sarif(raw_result()))
    (result,) = json.loads(out)["runs"][0]["results"]
    assert result["properties"] == {"secret_sha256": hashlib.sha256(SECRET.encode()).hexdigest()}
    assert result["message"] == {
        "text": f"github-pat has detected secret for file app/s.py at commit {SHA}."
    }
    assert result["locations"][0]["physicalLocation"]["region"] == {"startLine": 3, "endLine": 3}
    text = out.decode()
    for forbidden in (SECRET, "snippet", "someone@", "Some One", "sentinel", "commitMessage"):
        assert forbidden not in text


def test_adapt_without_a_commit_uses_the_message_without_it_and_relativizes_uris() -> None:
    result = raw_result(partialFingerprints={})
    result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = "/workspace/a/b.env"
    (out,) = json.loads(adapter.adapt(raw_sarif(result)))["runs"][0]["results"]
    assert out["message"]["text"] == "github-pat has detected secret for file a/b.env."
    assert out["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "a/b.env"


def test_adapt_ignores_an_untrusted_commit_value() -> None:
    result = raw_result(partialFingerprints={"commitSha": "x; rm -rf /"})
    (out,) = json.loads(adapter.adapt(raw_sarif(result)))["runs"][0]["results"]
    assert out["message"]["text"].endswith("for file app/s.py.")


def test_adapt_adds_the_notes_as_notifications() -> None:
    out = json.loads(adapter.adapt(raw_sarif(), notes=(adapter.SHALLOW_NOTE,)))
    notification = out["runs"][0]["invocations"][0]["toolExecutionNotifications"][0]
    assert notification == {"level": "warning", "message": {"text": adapter.SHALLOW_NOTE}}
    assert "invocations" not in json.loads(adapter.adapt(raw_sarif()))["runs"][0]


def test_adapt_output_is_sorted_and_stable() -> None:
    a, b = raw_result(), raw_result(ruleId="aws-access-token")
    assert adapter.adapt(raw_sarif(a, b)) == adapter.adapt(raw_sarif(b, a))


@pytest.mark.parametrize(
    "raw",
    [
        b"not json",
        b"[]",
        json.dumps({"version": "2.0.0", "runs": [{}]}).encode(),
        json.dumps({"version": "2.1.0", "runs": []}).encode(),
        raw_sarif({"ruleId": "x"}),
        raw_sarif(raw_result(ruleId="")),
        raw_sarif(raw_result(locations=[])),
        raw_sarif(
            raw_result(
                locations=[
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": "../x"},
                            "region": {"startLine": 1, "snippet": {"text": "v"}},
                        }
                    }
                ]
            )
        ),
        raw_sarif(
            raw_result(
                locations=[
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": "a"},
                            "region": {"startLine": 1},
                        }
                    }
                ]
            )
        ),
    ],
    ids=["not-json", "list", "version", "no-run", "no-location", "no-rule", "no-locs", "dotdot",
         "no-secret"],
)  # fmt: skip
def test_adapt_rejects_what_it_cannot_make_conforming(raw: bytes) -> None:
    with pytest.raises(adapter.InvalidOutput):
        adapter.adapt(raw)


# --- git ombra ---------------------------------------------------------------------------------


def git(*args: str, cwd: Path) -> None:
    env = {"PATH": os.environ["PATH"], "HOME": str(cwd), "GIT_CONFIG_GLOBAL": os.devnull}
    subprocess.run(["git", *args], cwd=cwd, env=env, check=True, capture_output=True)  # noqa: S603, S607


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    ws = tmp_path / "ws"
    ws.mkdir()
    git("init", "-q", "-b", "main", cwd=ws)
    (ws / "f").write_text("x\n")
    git("add", "-A", cwd=ws)
    git("-c", "user.name=a", "-c", "user.email=a@x.invalid", "commit", "-qm", "m", cwd=ws)
    return ws


def shadow_of(repo: Path, tmp_path: Path) -> tuple[Path, bool]:
    shadow = tmp_path / "shadow"
    shallow = adapter.build_shadow("git", repo / ".git", shadow, str(tmp_path))
    return shadow, shallow


def test_shadow_has_an_own_config_a_copied_head_and_links_to_the_data(
    repo: Path, tmp_path: Path
) -> None:
    (repo / ".git/config").write_text(
        '[core]\n\trepositoryformatversion = 0\n[diff "x"]\n\ttextconv = touch /tmp/pwned\n'
        '[gpg "ssh"]\n\tprogram = touch /tmp/pwned\n'
    )
    shadow, shallow = shadow_of(repo, tmp_path)
    assert shallow is False
    assert (shadow / "config").read_text() == (
        "[core]\n\trepositoryformatversion = 0\n\tbare = true\n"
    )
    assert (shadow / "HEAD").read_text() == (repo / ".git/HEAD").read_text()
    assert not (shadow / "HEAD").is_symlink()
    assert (shadow / "objects").readlink() == repo / ".git/objects"
    assert (shadow / "refs").readlink() == repo / ".git/refs"
    assert sorted(p.name for p in shadow.iterdir()) == ["HEAD", "config", "objects", "refs"]
    done = subprocess.run(  # noqa: S603 - la git dir ombra e' leggibile da git
        ["git", "--git-dir", str(shadow), "log", "--oneline"],  # noqa: S607
        env={"PATH": os.environ["PATH"], "GIT_CONFIG_GLOBAL": os.devnull},
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0 and len(done.stdout.splitlines()) == 1


def test_shadow_keeps_the_allowed_extensions_and_reports_a_shallow_clone(
    repo: Path, tmp_path: Path
) -> None:
    (repo / ".git/config").write_text(
        "[core]\n\trepositoryformatversion = 1\n[extensions]\n\tobjectformat = sha1\n"
        "\trefstorage = files\n\tpartialclone = origin\n"
    )
    (repo / ".git/shallow").write_text("0" * 40 + "\n")
    shadow, shallow = shadow_of(repo, tmp_path)
    assert shallow is True and (shadow / "shallow").is_symlink()
    text = (shadow / "config").read_text()
    assert "objectformat = sha1" in text and "refstorage = files" in text
    assert "partialclone" not in text and "origin" not in text


@pytest.mark.parametrize(
    "config",
    [
        "[core]\n\trepositoryformatversion = 2\n",
        "[extensions]\n\tobjectformat = md5\n",
        "[extensions]\n\trefstorage = custom\n",
    ],
    ids=["version", "objectformat", "refstorage"],
)
def test_shadow_rejects_formats_it_does_not_know(repo: Path, tmp_path: Path, config: str) -> None:
    (repo / ".git/config").write_text(config)
    with pytest.raises(adapter.UnsupportedRepo):
        shadow_of(repo, tmp_path)


def test_shadow_rejects_an_unusual_git_dir(repo: Path, tmp_path: Path) -> None:
    for mutate in (
        lambda: (repo / ".git/HEAD").write_text("ref: refs/heads/$(touch x)\n"),
        lambda: (repo / ".git/HEAD").write_text("ref: ../../etc/passwd\n"),
    ):
        mutate()
        with pytest.raises(adapter.UnsupportedRepo):
            adapter.build_shadow("git", repo / ".git", tmp_path / "s1", str(tmp_path))
    (repo / ".git/HEAD").unlink()
    os.symlink("/etc/hostname", repo / ".git/HEAD")
    with pytest.raises(adapter.UnsupportedRepo):
        adapter.build_shadow("git", repo / ".git", tmp_path / "s2", str(tmp_path))


def test_shadow_rejects_a_git_file_a_git_symlink_and_missing_objects(
    repo: Path, tmp_path: Path
) -> None:
    linked = tmp_path / "linked"
    linked.mkdir()
    os.symlink(repo / ".git", linked / ".git")
    plain = tmp_path / "plain"
    plain.mkdir()
    (plain / ".git").write_text("gitdir: /elsewhere\n")  # worktree collegato o sottomodulo
    for ws in (linked, plain):
        with pytest.raises(adapter.UnsupportedRepo):
            adapter.build_shadow("git", ws / ".git", tmp_path / f"s-{ws.name}", str(tmp_path))
    (repo / ".git/objects").rename(repo / ".git/objects-gone")
    with pytest.raises(adapter.UnsupportedRepo):
        adapter.build_shadow("git", repo / ".git", tmp_path / "s3", str(tmp_path))


# --- adattatore: esecuzione ---------------------------------------------------------------------


def fake_gitleaks(tmp_path: Path, body: str) -> str:
    script = tmp_path / "gitleaks"
    script.write_text(f"#!/bin/sh\n{body}\n")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return str(script)


def write_report(document: bytes, log: str = "", exit_code: int = 0) -> str:
    # `--report-path` e' l'argomento che segue l'opzione omonima: lo script lo cerca
    loop = 'while [ $# -gt 0 ]; do [ "$1" = --report-path ] && f=$2; shift; done'
    save = f"cat > \"$f\" <<'EOF'\n{document.decode()}\nEOF"
    return f"{loop}\n{save}\necho '{log}' >&2\nexit {exit_code}"


def run_adapter(tmp_path: Path, body: str, workspace: Path) -> tuple[int, Path]:
    out = tmp_path / "results.sarif"
    work = tmp_path / "tmp"
    work.mkdir(exist_ok=True)
    code = adapter.run(
        gitleaks=fake_gitleaks(tmp_path, body),
        git="git",
        config="/opt/ca-plugin/gitleaks.toml",
        workspace=str(workspace),
        out_file=str(out),
        tmp_dir=str(work),
    )
    return code, out


def test_run_git_mode_uses_the_shadow_and_the_hardened_arguments_and_environment(
    repo: Path, tmp_path: Path
) -> None:
    dump = tmp_path / "dump"
    body = f'echo "$@" > {dump}; env > {dump}.env; pwd > {dump}.cwd\n' + write_report(
        raw_sarif(raw_result()), "INF 1 commits scanned.", 1
    )
    code, out = run_adapter(tmp_path, body, repo)
    assert code == 0
    work = tmp_path / "tmp/gitleaks-work"
    argv = dump.read_text().split()
    assert argv[:2] == ["git", str(work / "shadow")]
    assert argv[argv.index("--config") + 1] == "/opt/ca-plugin/gitleaks.toml"
    assert argv[argv.index("--gitleaks-ignore-path") + 1] == str(work / "empty")
    assert "--ignore-gitleaks-allow" in argv
    assert not list((work / "empty").iterdir())
    for banned in ("--redact", "--log-opts", "safe.directory", "--no-git", "--exit-code"):
        assert banned not in argv
    env = dict(line.split("=", 1) for line in Path(f"{dump}.env").read_text().splitlines())
    assert env["GIT_CONFIG_NOSYSTEM"] == "1" and env["GIT_CONFIG_GLOBAL"] == os.devnull
    assert env["GIT_ATTR_NOSYSTEM"] == "1" and env["GIT_NO_LAZY_FETCH"] == "1"
    assert not {k for k in env if k.startswith("GIT_")} - {
        "GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_GLOBAL", "GIT_ATTR_NOSYSTEM", "GIT_NO_LAZY_FETCH",
    }  # fmt: skip
    assert Path(f"{dump}.cwd").read_text().strip() == str(work / "cwd")
    assert not list((work / "cwd").iterdir())
    assert json.loads(out.read_text())["runs"][0]["results"][0]["ruleId"] == "github-pat"


def test_run_without_git_scans_the_files_and_says_there_is_no_history(tmp_path: Path) -> None:
    ws = tmp_path / "plain"
    ws.mkdir()
    args = tmp_path / "args"
    code, out = run_adapter(
        tmp_path, f'echo "$@" > {args}\n' + write_report(raw_sarif(raw_result(), raw_result())), ws
    )
    assert code == 0 and args.read_text().split()[:2] == ["dir", str(ws)]
    notes = json.loads(out.read_text())["runs"][0]["invocations"][0]["toolExecutionNotifications"]
    assert notes[0]["message"]["text"] == adapter.NO_HISTORY_NOTE


def test_run_without_git_fails_when_a_gitleaksignore_is_present(tmp_path: Path) -> None:
    """N-07: `gitleaks dir` la legge sempre; un fallimento e' visibile, un risultato vuoto no."""
    ws = tmp_path / "plain"
    ws.mkdir()
    (ws / ".gitleaksignore").write_text("anything\n")
    ran = tmp_path / "ran"
    code, out = run_adapter(tmp_path, f"touch {ran}\n" + write_report(raw_sarif()), ws)
    assert (code, out.exists(), ran.exists()) == (adapter.EXIT_REPO, False, False)


def test_run_reports_a_shallow_clone(repo: Path, tmp_path: Path) -> None:
    (repo / ".git/shallow").write_text("0" * 40 + "\n")
    code, out = run_adapter(tmp_path, write_report(raw_sarif()), repo)
    notes = json.loads(out.read_text())["runs"][0]["invocations"][0]["toolExecutionNotifications"]
    assert code == 0 and notes[0]["message"]["text"] == adapter.SHALLOW_NOTE


@pytest.mark.parametrize(
    "log",
    [
        "ERR [git] fatal: detected dubious ownership in repository",
        "ERR [git] error: could not read object",
        "FTL [git] fatal: bad object HEAD",
        "WRN something dubious ownership",
    ],
    ids=["dubious", "git-err", "git-fatal", "dubious-in-warning"],
)
def test_run_a_git_error_in_the_log_fails_the_plugin_even_with_exit_0(
    repo: Path, tmp_path: Path, log: str
) -> None:
    code, out = run_adapter(tmp_path, write_report(raw_sarif(), log, 0), repo)
    assert (code, out.exists()) == (adapter.EXIT_TOOL, False)


def test_run_an_unrelated_info_line_is_not_an_error(repo: Path, tmp_path: Path) -> None:
    code, _ = run_adapter(tmp_path, write_report(raw_sarif(), "INF [git] 4 commits scanned."), repo)
    assert code == 0


def test_run_tool_error_without_output_and_missing_binary_are_exit_3(
    repo: Path, tmp_path: Path
) -> None:
    assert run_adapter(tmp_path, write_report(raw_sarif(), "", 126), repo)[0] == adapter.EXIT_TOOL
    assert run_adapter(tmp_path, "exit 0", repo)[0] == adapter.EXIT_TOOL
    code = adapter.run(
        gitleaks=str(tmp_path / "nope"),
        workspace=str(repo),
        out_file=str(tmp_path / "o"),
        tmp_dir=str(tmp_path),
    )
    assert code == adapter.EXIT_TOOL


def test_run_nonconforming_output_is_exit_5_and_unsupported_git_is_exit_6(
    repo: Path, tmp_path: Path
) -> None:
    code, out = run_adapter(tmp_path, "echo '{}' > \"$7\"; true", repo)
    assert code in (adapter.EXIT_INVALID, adapter.EXIT_TOOL) and not out.exists()
    (repo / ".git/config").write_text("[core]\n\trepositoryformatversion = 9\n")
    assert run_adapter(tmp_path, "exit 0", repo)[0] == adapter.EXIT_REPO


def test_run_never_leaks_stderr_or_stdout(
    repo: Path, tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    body = "echo token=abc; " + write_report(raw_sarif(raw_result()), "INF token=abc", 1)
    run_adapter(tmp_path, body, repo)
    assert capfd.readouterr() == ("", "")


def test_adapter_does_not_import_ca_core() -> None:
    text = (GITLEAKS / "gitleaks_adapter.py").read_text()
    assert not re.search(r"^\s*(?:from|import)\s+ca_", text, re.M)


# --- immagine (statico) -------------------------------------------------------------------


def test_dockerfile_pins_base_binary_config_and_labels() -> None:
    text = (GITLEAKS / "Dockerfile").read_text()
    froms = re.findall(r"^FROM\s+(?:--platform=\S+\s+)?(\S+)", text, re.M)
    assert len(froms) == 2 and all(re.search(r"@sha256:[0-9a-f]{64}$", f) for f in froms)
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    assert "latest" not in code.lower()
    assert f"--checksum=sha256:{TARBALL_SHA256}" in text and "gitleaks_8.30.1_linux_x64" in text
    assert "/v8.30.1/config/gitleaks.toml" in text
    assert 'ca.engines="gitleaks"' in text and "org.opencontainers.image.licenses" not in text
    assert "USER 65534:65534" in text
    assert re.search(r'^ENTRYPOINT \["python", "/opt/ca-plugin/gitleaks_adapter.py"\]$', text, re.M)


def test_build_context_contains_only_what_the_image_needs() -> None:
    assert (GITLEAKS / ".dockerignore").read_text().split() == [
        "*",
        "!gitleaks_adapter.py",
        "!licenses",
    ]


def test_license_files_are_the_release_texts_without_a_product_license() -> None:
    notices = " ".join((GITLEAKS / "licenses/THIRD-PARTY-NOTICES.md").read_text().split())
    assert "MIT" in notices and "non dichiara la licenza del prodotto" in notices.lower()
    licence = (GITLEAKS / "licenses/gitleaks/LICENSE").read_text()
    assert licence.startswith("MIT License") and "Zachary Rice" in licence

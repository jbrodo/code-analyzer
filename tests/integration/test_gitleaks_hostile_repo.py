"""P-07 / M-08: un repository con configurazione git ostile non fa eseguire comandi al plugin.

Sull'immagine reale (`CA_TEST_DOCKER=1`), con `docker run` e il profilo del runner (rete assente,
root in sola lettura, `/tmp` tmpfs, utente 65534) piu' una cartella di marcatori che solo il test
monta in scrittura: un comando eseguito dal repository lascia un file li'. Ogni vettore ha il suo
controllo positivo: lo stesso repository, letto direttamente da git nella stessa immagine con
`safe.directory` (la strada scartata), crea il marcatore, quindi il test non passa per un vettore
spento. Il repository e' del proprietario dell'host, non di 65534: e' anche la prova di "altro
proprietario" senza `safe.directory`.
"""

import json
import os
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest
from plugin_image_support import build_image, needs_docker
from plugin_image_support import secrets_history as sh

PLUGIN = "gitleaks"
TAG = "localhost/ca-plugin-gitleaks:hostile"
pytestmark = needs_docker
GENERIC_ENV = ["--env", "GIT_CONFIG_COUNT=1", "--env", "GIT_CONFIG_KEY_0=safe.directory"]


@pytest.fixture(scope="module")
def image_id() -> Iterator[str]:
    yield from build_image(PLUGIN, TAG)


def profile(ws: Path, out: Path, markers: Path) -> list[str]:
    for d in (out, markers):
        d.mkdir(exist_ok=True)
        d.chmod(0o777)
    return [
        "docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--user", "65534:65534",
        "--tmpfs", "/tmp:rw,noexec,nosuid", "--env", "HOME=/tmp",
        "--mount", f"type=bind,src={ws},dst=/workspace,readonly",
        "--mount", f"type=bind,src={out},dst=/out",
        "--mount", f"type=bind,src={markers},dst=/markers",
    ]  # fmt: skip


def plugin(image_id: str, ws: Path, root: Path) -> tuple[int, dict[str, object] | None, Path]:
    out, markers = root / "out", root / "markers"
    cmd = [*profile(ws, out, markers), image_id]
    done = subprocess.run(cmd, capture_output=True, check=False, timeout=300)  # noqa: S603
    report = out / "results.sarif"
    return done.returncode, json.loads(report.read_text()) if report.exists() else None, markers


def native(image_id: str, ws: Path, root: Path, *argv: str, entrypoint: str) -> None:
    """La strada scartata: git o gitleaks direttamente sul workspace, con `safe.directory`."""
    cmd = [
        *profile(ws, root / "out", root / "markers"), "--workdir", "/workspace",
        *GENERIC_ENV, "--env", "GIT_CONFIG_VALUE_0=/workspace",
        "--entrypoint", entrypoint, image_id, *argv,
    ]  # fmt: skip
    subprocess.run(cmd, capture_output=True, check=False, timeout=300)  # noqa: S603


def new_repo(tmp_path: Path) -> sh.SecretsHistory:
    history = sh.build_history(tmp_path / "ws")
    return history


def git_config(ws: Path, *args: str) -> None:
    subprocess.run(  # noqa: S603
        ["git", "config", "--file", str(ws / ".git/config"), *args],  # noqa: S607
        check=True,
        capture_output=True,
    )


def marker(cmd_name: str) -> str:
    return f"touch /markers/{cmd_name}"


def commit_all(ws: Path, message: str) -> None:
    env = {
        **sh._git_env(ws.parent),
        "GIT_AUTHOR_NAME": "F", "GIT_AUTHOR_EMAIL": "f@example.invalid",
        "GIT_COMMITTER_NAME": "F", "GIT_COMMITTER_EMAIL": "f@example.invalid",
    }  # fmt: skip
    sh.git(ws, "add", "-A", env=env)
    sh.git(ws, "commit", "-q", "--no-verify", "-m", message, env=env)


def sign_head(ws: Path) -> None:
    """Riscrive il commit di HEAD con un'intestazione `gpgsig` finta (non e' una firma valida)."""
    raw = sh.git(ws, "cat-file", "commit", "HEAD")
    head, _, message = raw.partition("\n\n")
    signature = "gpgsig -----BEGIN SSH SIGNATURE-----\n AAAA\n -----END SSH SIGNATURE-----"
    new = f"{head}\n{signature}\n\n{message}\n"
    done = subprocess.run(  # noqa: S603
        ["git", "-C", str(ws), "hash-object", "-t", "commit", "-w", "--stdin"],  # noqa: S607
        input=new,
        text=True,
        capture_output=True,
        check=True,
        env=sh._git_env(ws.parent),
    )
    sh.git(ws, "update-ref", "refs/heads/main", done.stdout.strip())


def prepare_textconv(ws: Path) -> None:
    (ws / ".gitattributes").write_text("* diff=evil\n")
    commit_all(ws, "attributes")
    git_config(ws, "diff.evil.textconv", f"sh -c '{marker('textconv')}; cat \"$1\"' --")


def prepare_signature(ws: Path) -> None:
    sign_head(ws)
    git_config(ws, "log.showSignature", "true")
    git_config(ws, "gpg.format", "ssh")
    program = ws / ".git/sigprog.sh"  # il repository porta il proprio programma di firma
    program.write_text(f"#!/bin/sh\n{marker('signature')}\nexit 1\n")
    program.chmod(0o755)
    git_config(ws, "gpg.ssh.program", "/workspace/.git/sigprog.sh")
    git_config(ws, "gpg.ssh.allowedSignersFile", "/etc/hostname")  # deve esistere


def prepare_promisor(ws: Path) -> None:
    objects = ws / ".git/objects"
    blob = sh.git(ws, "rev-parse", "HEAD:README.md")
    (objects / blob[:2] / blob[2:]).chmod(0o644)
    (objects / blob[:2] / blob[2:]).unlink()  # blob mancante: git prova a prenderlo dal promisor
    git_config(ws, "core.repositoryformatversion", "1")
    git_config(ws, "extensions.partialClone", "origin")
    program = ws / ".git/extprog.sh"
    program.write_text(f"#!/bin/sh\n{marker('promisor')}\nexit 1\n")
    program.chmod(0o755)
    git_config(ws, "remote.origin.url", "ext::/workspace/.git/extprog.sh")
    git_config(ws, "remote.origin.promisor", "true")
    git_config(ws, "remote.origin.partialclonefilter", "blob:none")  # evita di scrivere la config
    git_config(ws, "protocol.ext.allow", "always")


def prepare_fsmonitor(ws: Path) -> None:
    git_config(ws, "core.fsmonitor", marker("fsmonitor"))


def prepare_pager(ws: Path) -> None:
    git_config(ws, "core.pager", marker("pager"))
    git_config(ws, "pager.log", "true")


VECTORS = {
    "textconv": prepare_textconv,
    "signature": prepare_signature,
    "promisor": prepare_promisor,
    "fsmonitor": prepare_fsmonitor,
    "pager": prepare_pager,
}
CONTROLLED = {"textconv", "signature", "promisor"}  # git diretto li esegue (ADR-0012, misure)


@pytest.mark.parametrize("vector", VECTORS)
def test_no_hostile_config_vector_runs_a_command_under_the_plugin(
    image_id: str, tmp_path: Path, vector: str
) -> None:
    history = new_repo(tmp_path)
    VECTORS[vector](history.path)
    if vector in CONTROLLED:  # controllo positivo: la strada scartata esegue il comando
        native(image_id, history.path, tmp_path, "log", "-p", "--all", "--full-history",
               entrypoint="git")  # fmt: skip
        assert (tmp_path / "markers" / vector).exists(), f"vettore {vector} spento"
        (tmp_path / "markers" / vector).unlink()
    code, report, markers = plugin(image_id, history.path, tmp_path)
    assert sorted(p.name for p in markers.iterdir()) == []
    if vector == "promisor":
        assert code != 0 and report is None  # blob mancante: fallito, non pulito
    else:
        assert code == 0 and report is not None
        assert {r["ruleId"] for r in report["runs"][0]["results"]} == {"github-pat", "gitlab-pat"}


def test_secret_only_on_another_branch_is_found(image_id: str, tmp_path: Path) -> None:
    history = new_repo(tmp_path)
    ws = history.path
    other = sh.fake_secrets("another-seed")["PAT"]
    sh.git(ws, "checkout", "-q", "-b", "side")
    (ws / "side.env").write_text(f"GITHUB_TOKEN={other.value}\n")
    commit_all(ws, "side secret")
    sh.git(ws, "checkout", "-q", "main")
    code, report, _ = plugin(image_id, ws, tmp_path)
    assert code == 0 and report is not None
    hashes = {r["properties"]["secret_sha256"] for r in report["runs"][0]["results"]}
    assert other.sha256 in hashes  # trovato con `--all`, nessuna perdita di copertura
    assert {s.sha256 for s in history.secrets.values()} <= hashes


def test_hostile_gitleaks_toml_and_gitleaksignore_have_no_effect(
    image_id: str, tmp_path: Path
) -> None:
    history = new_repo(tmp_path)
    ws = history.path
    (ws / ".gitleaks.toml").write_text("[allowlist]\nregexes = ['''.*''']\n")
    # controllo positivo 1: gitleaks diretto sul workspace onora `.gitleaks.toml`
    native(image_id, ws, tmp_path, "git", "/workspace", "--no-banner", "--report-format", "json",
           "--report-path", "/out/native.json", entrypoint="gitleaks")  # fmt: skip
    assert json.loads((tmp_path / "out/native.json").read_text()) == []
    (ws / ".gitleaks.toml").unlink()
    # controllo positivo 2: ricavate le impronte, `.gitleaksignore` le nasconde a gitleaks diretto
    native(image_id, ws, tmp_path, "git", "/workspace", "--no-banner", "--report-format", "json",
           "--report-path", "/out/all.json", entrypoint="gitleaks")  # fmt: skip
    leaks = json.loads((tmp_path / "out/all.json").read_text())
    assert len(leaks) >= 3
    (ws / ".gitleaksignore").write_text("\n".join(leak["Fingerprint"] for leak in leaks) + "\n")
    (ws / ".gitleaks.toml").write_text("[allowlist]\nregexes = ['''.*''']\n")
    native(image_id, ws, tmp_path, "git", "/workspace", "--no-banner", "--report-format", "json",
           "--report-path", "/out/ignored.json", entrypoint="gitleaks")  # fmt: skip
    assert json.loads((tmp_path / "out/ignored.json").read_text()) == []
    code, report, _ = plugin(image_id, ws, tmp_path)  # stesso repository, sotto il plugin
    assert code == 0 and report is not None
    assert len(report["runs"][0]["results"]) == len(leaks)


def test_gitleaksignore_in_dir_mode_fails_the_plugin_instead_of_hiding_secrets(
    image_id: str, tmp_path: Path
) -> None:
    """N-07: `gitleaks dir` legge `<target>/.gitleaksignore` anche con `--gitleaks-ignore-path`."""
    ws = new_repo(tmp_path).path
    shutil.rmtree(ws / ".git")  # senza `.git` il plugin usa `gitleaks dir`
    dir_cmd = ["dir", "/workspace", "--no-banner", "--report-format", "json"]
    native(image_id, ws, tmp_path, *dir_cmd, "--report-path", "/out/dir.json",
           entrypoint="gitleaks")  # fmt: skip
    leaks = json.loads((tmp_path / "out/dir.json").read_text())
    assert len(leaks) >= 1
    code, report, _ = plugin(image_id, ws, tmp_path)  # pulito: la modalita' dir funziona
    assert code == 0 and report is not None and len(report["runs"][0]["results"]) == len(leaks)
    (ws / ".gitleaksignore").write_text("\n".join(leak["Fingerprint"] for leak in leaks) + "\n")
    native(image_id, ws, tmp_path, *dir_cmd, "--report-path", "/out/dir2.json",
           entrypoint="gitleaks")  # fmt: skip
    assert json.loads((tmp_path / "out/dir2.json").read_text()) == []  # controllo positivo
    (tmp_path / "out/results.sarif").unlink()  # quello della prova pulita
    code, report, _ = plugin(image_id, ws, tmp_path)
    assert code == 6 and report is None  # un fallimento visibile, non un risultato vuoto


def test_workspace_of_another_owner_is_read_without_safe_directory(
    image_id: str, tmp_path: Path
) -> None:
    history = new_repo(tmp_path)
    assert history.path.stat().st_uid not in (0, 65534)  # altro proprietario rispetto al plugin
    code, report, _ = plugin(image_id, history.path, tmp_path)
    assert code == 0 and report is not None and len(report["runs"][0]["results"]) == 3
    # controllo positivo: lo stesso repository, senza `safe.directory`, per git e' "dubious"
    probe = subprocess.run(  # noqa: S603
        [*profile(history.path, tmp_path / "o2", tmp_path / "m2"), "--workdir", "/workspace",
         "--entrypoint", "git", image_id, "log", "--oneline"],
        capture_output=True, text=True, check=False,
    )  # fmt: skip
    assert "dubious ownership" in probe.stderr


def test_partial_clone_fails_the_plugin(image_id: str, tmp_path: Path) -> None:
    history = new_repo(tmp_path / "src")
    sh.git(history.path, "config", "uploadpack.allowFilter", "true")
    sh.git(history.path, "config", "uploadpack.allowAnySHA1InWant", "true")
    clone = tmp_path / "clone"
    subprocess.run(  # noqa: S603
        ["git", "clone", "-q", "--filter=blob:none", "--no-checkout", f"file://{history.path}",  # noqa: S607
         str(clone)],
        check=True, capture_output=True, env={**os.environ, "GIT_CONFIG_GLOBAL": os.devnull},
    )  # fmt: skip
    code, report, _ = plugin(image_id, clone, tmp_path)
    assert code != 0 and report is None

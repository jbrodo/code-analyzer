"""I-04: il pacchetto costruito da `package-cli.sh` funziona da solo, senza le cablature di prova.

Lancia `bin/code-analyzer` dell'installazione pulita, fuori dal repository: nessun `_cli_child.py`,
manifest e registry sono quelli del pacchetto. `UV_OFFLINE`: dipendenze dalla cache di uv.

I-01: dallo stesso pacchetto si costruisce l'immagine CLI, che scansiona la fixture con i plugin
come container fratelli (ADR-0004, M-11). Serve il socket del daemon in `/var/run/docker.sock`.
"""

import json
import os
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from .e2e_lab import (
    BUILTIN,
    COSIGN,
    DEPLOY,
    SYFT,
    Fleet,
    container_leftovers,
    copy_fixture,
    e2e_marks,
    make_feeds_cache,
    needs_feeds,
    sh,
)

pytestmark = [*e2e_marks, needs_feeds]
# eslint si applica solo a JS e TS: la fixture Python non lo avvia.
NOT_APPLICABLE = {"eslint"}
PLUGINS = len(list(BUILTIN.glob("*/plugin.yaml")))  # tutti i plugin impacchettati


SOCKET = Path("/var/run/docker.sock")


@pytest.fixture(scope="module")
def package(fleet: Fleet, work: Path) -> tuple[Path, dict[str, str]]:
    """Uscita di `package-cli.sh` e immagini firmate, una volta per i due test."""
    fleet.add_builtin("syft")  # avvia il registry locale e crea le chiavi di prova
    out = work / "package"
    sh(
        str(DEPLOY / "package-cli.sh"), str(out),
        env={**fleet.env, "SYFT": SYFT, "UV_OFFLINE": "1"},
    )  # fmt: skip
    images = dict(line.split() for line in (out / "images.txt").read_text().splitlines())
    assert len(images) == PLUGINS and all("@sha256:" in image for image in images.values())
    return out, images


def test_packaged_cli_scans_a_fixture_with_its_own_manifests(
    work: Path, package: tuple[Path, dict[str, str]]
) -> None:
    out, images = package

    xdg = work / "package-xdg"
    digests = {name: image.rsplit("@", 1)[1] for name, image in images.items()}
    make_feeds_cache(xdg / "code-analyzer" / "feeds", digests)
    root = copy_fixture("python-app", work / "package-repo", license_policy=True)
    reports = work / "package-out"
    env = {
        **os.environ,
        "COSIGN": COSIGN,
        "CA_COSIGN_PUBLIC_KEY": str(out / "cosign.pub"),
        "XDG_CACHE_HOME": str(xdg),
    }

    def cli(*argv: str) -> subprocess.CompletedProcess[str]:
        command = [str(out / "venv/bin/code-analyzer"), *argv]
        return subprocess.run(
            command, capture_output=True, text=True, env=env, cwd=work, timeout=900
        )

    scan = cli("scan", str(root), "--offline", "--output-dir", str(reports))
    assert scan.returncode == 0, scan.stderr[-2000:]
    report = json.loads((reports / "code-analyzer.report.json").read_text())
    assert report["status"] == "complete"
    assert {p["name"] for p in report["plugins"]} == set(images) - NOT_APPLICABLE
    assert all(p["outcome"] == "ok" and p["signature"] == "verified" for p in report["plugins"])
    assert cli("gate", "--report", str(reports / "code-analyzer.report.json")).returncode == 1

    bom = work / "package-bom.json"
    assert cli("sbom", str(root), "--output", str(bom)).returncode == 0
    assert json.loads(bom.read_text())["specVersion"] == "1.7"


@pytest.fixture(scope="module")
def cli_image(fleet: Fleet, work: Path, package: tuple[Path, dict[str, str]]) -> str:
    """L'immagine CLI costruita dal pacchetto (con `ca-integrations`), una volta per modulo."""
    out, _ = package
    tag = f"localhost/ca-e2e-cli:{fleet.project}"
    sh(
        str(DEPLOY / "cli/build-cli-image.sh"), str(out), tag, str(work / "cli-sbom"),
        env={"SYFT": SYFT, "UV_OFFLINE": "1"},
    )  # fmt: skip
    fleet.refs.append(tag)  # rimossa alla chiusura della flotta
    return tag


def test_cli_image_scans_with_sibling_plugin_containers(
    work: Path, package: tuple[Path, dict[str, str]], cli_image: str
) -> None:
    out, images = package
    tag = cli_image

    cache = work / "image-cache"
    make_feeds_cache(cache, {name: image.rsplit("@", 1)[1] for name, image in images.items()})
    root = copy_fixture("python-app", work / "image-repo", license_policy=True)
    scratch, reports, other = work / "image-work", work / "image-out", work / "image-other"
    for folder in (scratch, reports, other):
        folder.mkdir(mode=0o700)

    def image(*argv: str, host_workspace: Path = root) -> subprocess.CompletedProcess[str]:
        command = [
            "docker", "run", "--rm",
            "--user", f"{os.getuid()}:{os.getgid()}",
            "--group-add", str(SOCKET.stat().st_gid),
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--read-only", "--tmpfs", "/tmp",
            "--network", "host",  # il registry di prova e' su loopback
            "-v", f"{SOCKET}:{SOCKET}",
            "-v", f"{root}:/ca/workspace:ro",
            "-v", f"{scratch}:/ca/work",
            "-v", f"{cache}:/ca/cache",
            "-v", f"{reports}:/ca/output",
            "-v", f"{out / 'cosign.pub'}:/ca/keys/cosign.pub:ro",
            "-e", "CA_COSIGN_PUBLIC_KEY=/ca/keys/cosign.pub",
            "-e", f"CA_HOST_WORKSPACE={host_workspace}",
            "-e", f"CA_HOST_WORK={scratch}",
            "-e", f"CA_HOST_CACHE={cache}",
            tag, *argv,
        ]  # fmt: skip
        return subprocess.run(command, capture_output=True, text=True, timeout=900)

    scan = image("scan", "--offline")
    assert scan.returncode == 0, scan.stderr[-2000:]
    report = json.loads((reports / "code-analyzer.report.json").read_text())
    assert report["status"] == "complete"
    assert {p["name"] for p in report["plugins"]} == set(images) - NOT_APPLICABLE
    assert all(p["outcome"] == "ok" and p["signature"] == "verified" for p in report["plugins"])
    assert any(f["category"] == "dependency" for f in report["findings"])  # feed montati
    assert image("gate").returncode == 1  # legge il report da /ca/output
    assert list(scratch.iterdir()) == []  # radice di lavoro ripulita
    assert not list(cache.glob(".ca-probe-*"))

    # Il daemon monterebbe un'altra directory: la scansione si annulla prima di ogni plugin.
    (reports / "code-analyzer.report.json").unlink()
    wrong = image("scan", "--offline", host_workspace=other)
    assert wrong.returncode == 2 and "non corrispondono" in wrong.stderr
    assert not (reports / "code-analyzer.report.json").exists()
    assert container_leftovers() == []


class FakeGitHub:
    """Un GitHub minimo su loopback: commenti di una PR e check run. Registra le richieste."""

    def __init__(self) -> None:
        self.comments: list[dict[str, Any]] = []
        self.checks: list[dict[str, Any]] = []
        self.requests: list[tuple[str, str]] = []
        self.tokens: set[str] = set()
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: object) -> None:
                pass

            def _reply(self, status: int, payload: object) -> None:
                body = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _body(self) -> dict[str, Any]:
                data = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                assert isinstance(data, dict)
                return data

            def _note(self) -> None:
                fake.requests.append((self.command, self.path))
                fake.tokens.add(self.headers.get("Authorization", ""))

            def do_GET(self) -> None:  # noqa: N802
                self._note()
                self._reply(200, fake.comments)

            def do_POST(self) -> None:  # noqa: N802
                self._note()
                body = self._body()
                if self.path.endswith("/check-runs"):
                    fake.checks.append(body)
                    self._reply(201, {"id": len(fake.checks)})
                    return
                comment = {"id": 100 + len(fake.comments), "body": body["body"],
                           "user": {"login": "github-actions[bot]"}}  # fmt: skip
                fake.comments.append(comment)
                self._reply(201, comment)

            def do_PATCH(self) -> None:  # noqa: N802
                self._note()
                ident = int(self.path.rsplit("/", 1)[1])
                comment = next(c for c in fake.comments if c["id"] == ident)
                comment["body"] = self._body()["body"]
                self._reply(200, comment)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def _git(root: Path, *argv: str) -> str:
    return subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-C", str(root), *argv],
        check=True, capture_output=True, text=True,
    ).stdout.strip()  # fmt: skip


def test_action_scripts_run_against_the_real_image(
    work: Path, package: tuple[Path, dict[str, str]], cli_image: str
) -> None:
    """N-05, parte locale: gli script dell'Action con l'immagine vera, `gh` e GitHub assenti.

    Riproduce una PR (commit di merge con base come primo genitore), la scansione del base come
    baseline, `scan --pr`, `notify` su un GitHub finto su loopback e `gate`. La parte che prova
    il comportamento di GitHub vero (commento, check run, SARIF) è il workflow `e2e-action.yml`.
    """
    out, images = package
    cache = work / "action-cache"
    make_feeds_cache(cache, {name: image.rsplit("@", 1)[1] for name, image in images.items()})
    repo = copy_fixture("python-app", work / "action-repo", license_policy=True)
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")
    _git(repo, "checkout", "-q", "-b", "pr")
    added = repo / "app" / "pr_added.py"
    added.write_text("import subprocess\n\n\ndef run(cmd):\n    subprocess.call(cmd, shell=True)\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "pr")
    head = _git(repo, "rev-parse", "HEAD")
    _git(repo, "checkout", "-q", "main")
    _git(repo, "merge", "-q", "--no-ff", "-m", "merge", "pr")
    assert _git(repo, "rev-parse", "HEAD^1") == base and _git(repo, "rev-parse", "HEAD^2") == head

    root = work / "action-root"
    scratch, reports = root / "work", root / "output"
    for folder in (root, scratch, reports):
        folder.mkdir(mode=0o700, exist_ok=True)
    event = work / "action-event.json"
    event.write_text(json.dumps({"pull_request": {"number": 3, "head": {"sha": head}}}))
    github = FakeGitHub()
    action = DEPLOY.parents[1] / "integrations" / "github-action"
    env = {
        **os.environ,
        "CA_IMAGE": cli_image, "CA_WORKSPACE": str(repo), "CA_WORK": str(scratch),
        "CA_CACHE": str(cache), "CA_OUTPUT": str(reports),
        "CA_PUBLIC_KEY": str(out / "cosign.pub"), "CA_NETWORK": "host", "CA_OFFLINE": "true",
        "BASE_SHA": base, "CA_SCAN_ROOT": str(root), "CA_BASELINE_DIR": str(reports / "baseline"),
        "GITHUB_TOKEN": "ghs_e2e_token", "GITHUB_REPOSITORY": "acme/shop",
        "GITHUB_API_URL": github.url, "CA_NOTIFY_ALLOW_LOOPBACK_HTTP": "1",
        "GITHUB_EVENT_PATH": str(event), "GITHUB_STEP_SUMMARY": str(work / "summary.md"),
    }  # fmt: skip
    (work / "summary.md").write_text("")

    def cli(script: str, *argv: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(action / script), *argv],
            capture_output=True, text=True, env=env, timeout=1800,
        )  # fmt: skip

    try:
        assert cli("scan-base.sh").returncode == 0
        baseline = json.loads((reports / "baseline/code-analyzer.report.json").read_text())
        assert baseline["repository"]["commit"] == base and baseline["scan"]["kind"] == "full"

        scan = cli(
            "run-cli.sh", "scan", "--output-dir", "/ca/output", "--pr", "--base", base,
            "--pull-request", "3", "--baseline", "/ca/output/baseline/code-analyzer.report.json",
            "--baseline-source", "base-scan",
        )  # fmt: skip
        assert scan.returncode == 0, scan.stderr[-2000:]
        report = json.loads((reports / "code-analyzer.report.json").read_text())
        assert report["baseline"]["status"] == "valid", report["baseline"]
        assert report["gate"]["effective_mode"] in ("new-findings-only", "all")
        states = {f["baseline_state"] for f in report["findings"]}
        assert "new" in states and "existing" in states
        new_paths = {f["location"]["path"] for f in report["findings"]
                     if f["baseline_state"] == "new" and f.get("location")}  # fmt: skip
        assert "app/pr_added.py" in new_paths

        assert (reports / "code-analyzer.sarif").is_file()
        for _ in range(2):  # la seconda volta aggiorna il commento, non ne crea un altro
            notify = cli("run-cli.sh", "notify", "--provider", "github",
                         "--report", "/ca/output/code-analyzer.report.json")  # fmt: skip
            assert notify.returncode == 0, notify.stderr[-2000:]
        assert len(github.comments) == 1
        assert github.comments[0]["body"].startswith("<!-- code-analyzer:1 -->")
        assert "app/pr_added.py" in github.comments[0]["body"].replace("\\", "")
        assert [c["head_sha"] for c in github.checks] == [head, head]
        assert github.checks[0]["conclusion"] == "failure"
        assert github.tokens == {"Bearer ghs_e2e_token"}
        assert "ghs_e2e_token" not in notify.stdout + notify.stderr

        gate = cli("run-cli.sh", "gate")
        assert gate.returncode == 1  # il gate è l'unico a decidere

        # N-06 con dati veri: l'SBOM 1.7 di syft riportato alla 1.6 e i report su finding reali.
        sbom = cli("run-cli.sh", "sbom", "--output", "/ca/output/sbom.cdx.json")
        assert sbom.returncode == 0, sbom.stderr[-2000:]
        export = cli(
            "run-cli.sh", "export", "--format", "gitlab",
            "--sbom", "/ca/output/sbom.cdx.json", "--output-dir", "/ca/output",
        )  # fmt: skip
        assert export.returncode == 0, export.stderr[-2000:]
        assert (
            json.loads((reports / "gl-sbom-code-analyzer.cdx.json").read_text())["specVersion"]
            == "1.6"
        )
        sast = json.loads((reports / "gl-sast-report.json").read_text())
        dependency = json.loads((reports / "gl-dependency-scanning-report.json").read_text())
        assert any(v["location"]["file"] == "app/pr_added.py" for v in sast["vulnerabilities"])
        assert dependency["vulnerabilities"], export.stderr
        assert (reports / "gl-code-quality-report.json").is_file()
    finally:
        github.close()
    assert container_leftovers() == []

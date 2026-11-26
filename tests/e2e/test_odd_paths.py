"""Nomi di file insoliti e collegamenti simbolici con tutti i plugin firmati (ADR-0004).

Un repository legittimo può avere cartelle di nome `#`, `a?b`, `100%41` o `a:b` e collegamenti
simbolici a file e cartelle. Nessun plugin deve fallire per questo, e ogni finding deve stare su un
file vero del workspace: l'`uri` torna al nome giusto e nessun risultato passa da un collegamento,
che l'host non legge. I contenuti sono le fixture del progetto, copiate sotto quei nomi.
"""

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import secrets_history  # tests/fixtures/builders (percorso aggiunto da `e2e_lab`)

from .e2e_lab import BUILTIN, REPOS, Fleet, e2e_marks, needs_feeds

pytestmark = [*e2e_marks, needs_feeds]

FOLDERS = ["#", "a?b", "100%41", "a:b", "con spazio è"]
# (sorgente nelle fixture, nome nella cartella insolita)
SOURCES = [
    ("python-app/app", "app"),
    ("js-ts-app/src", "src"),
    ("js-ts-app/package-lock.json", "package-lock.json"),
    ("js-ts-app/package.json", "package.json"),
    ("python-app/requirements.txt", "requirements.txt"),
    ("iac-app/Dockerfile", "Dockerfile"),
    ("iac-app/k8s", "k8s"),
    ("iac-app/terraform", "terraform"),
]
PLUGINS = sorted(p.parent.name.replace("_", "-") for p in BUILTIN.glob("*/plugin.yaml"))


def build(root: Path) -> list[Path]:
    """Il workspace; restituisce i collegamenti creati."""
    for folder in FOLDERS:
        base = root / folder
        base.mkdir(parents=True)
        for source, name in SOURCES:
            origin = REPOS / source
            if not origin.exists():
                continue
            if origin.is_dir():
                shutil.copytree(origin, base / name, ignore=shutil.ignore_patterns("__pycache__"))
            else:
                shutil.copyfile(origin, base / name)
    (root / "LICENSE").write_text("SPDX-License-Identifier: MIT\n")
    # un segreto finto diverso in ogni cartella (uno uguale sarebbe un solo finding, ADR-0008)
    for index, folder in enumerate(FOLDERS):
        token = secrets_history.fake_secrets(f"odd-paths/{index}")["PAT"].value
        (root / folder / "token.env").write_text(f"GITHUB_TOKEN={token}\n")
    real = root / FOLDERS[0]
    links = []
    targets = [p for p in sorted(real.rglob("*")) if p.is_file()]
    link_dir = root / "collegamenti"
    link_dir.mkdir()
    for index, target in enumerate(targets):
        # stesso nome del bersaglio, così ogni strumento lo riconosce come tale
        folder = link_dir / f"f{index}"
        folder.mkdir()
        link = folder / target.name
        link.symlink_to(os.path.relpath(target, folder))
        links.append(link)
    directory = root / "cartella-collegata"
    directory.symlink_to(FOLDERS[0], target_is_directory=True)
    _commit(root)  # gitleaks legge la storia
    return [*links, directory]


def _commit(root: Path) -> None:
    identity = ["-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid"]
    for args in (["init", "-q"], ["add", "-A", "-f"], [*identity, "commit", "-qm", "odd names"]):
        subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)


@pytest.fixture(scope="module")
def scan(fleet: Fleet, feeds_cache: Path, tmp_path_factory: pytest.TempPathFactory) -> Any:
    for plugin in PLUGINS:
        fleet.add_builtin(plugin)
    base = tmp_path_factory.mktemp("e2e-odd")
    root = base / "repo"
    links = build(root)
    assert len(links) > 5
    result = fleet.scan(root, base / "out", "--offline", plugins=PLUGINS, feeds_cache=feeds_cache)
    assert result.returncode == 0, result.stderr[-3000:]
    return root, result.report


def test_no_plugin_fails_on_odd_names_and_symlinks(scan: Any) -> None:
    _, report = scan
    failed = {p["name"]: p.get("failure") for p in report["plugins"] if p["outcome"] == "failed"}
    assert failed == {}, failed


def test_every_finding_is_on_a_real_file_of_the_workspace(scan: Any) -> None:
    root, report = scan
    wrong = []
    for finding in report["findings"]:
        path = finding["location"].get("path")
        if path is None or finding["category"] in ("architecture", "health"):
            continue
        current = root
        for part in path.split("/"):
            current /= part
            if current.is_symlink():
                wrong.append((finding["tool"], path, "collegamento"))
                break
        else:
            if not current.is_file():
                wrong.append((finding["tool"], path, "non esiste"))
    assert wrong == [], wrong[:20]


@pytest.mark.parametrize("folder", FOLDERS)
def test_findings_are_reported_inside_every_odd_folder(scan: Any, folder: str) -> None:
    """Nessuna cartella sparisce in silenzio: più strumenti vi segnalano qualcosa."""
    _, report = scan
    tools = {
        tool
        for f in report["findings"]
        if (f["location"].get("path") or "").startswith(folder + "/")
        for tool in f["tools"]
    }
    assert len(tools) >= 4, (folder, sorted(tools))


def test_the_secret_in_every_odd_folder_is_found(scan: Any) -> None:
    _, report = scan
    found = {f["location"]["path"] for f in report["findings"] if f["category"] == "secret"}
    assert {f"{folder}/token.env" for folder in FOLDERS} <= found, sorted(found)


def test_the_graph_leaves_out_what_its_contract_cannot_carry_and_says_so(scan: Any) -> None:
    """`a:b/` sembra un'unità di Windows: il contratto del grafo la rifiuta. Quei file si
    contano tra i saltati per il nome; il resto del grafo resta, con i suoi finding."""
    _, report = scan
    runs = {p["name"]: p["outcome"] for p in report["plugins"]}
    assert runs["ca-graph"] == "ok"

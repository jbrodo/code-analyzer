"""Strumenti del golden set: campione riproducibile e senza copie di codice, annotazione che non
perde né riscrive risposte, server solo locale. Dati e repository finti."""

import importlib.util
import json
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from collections.abc import Iterator
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from ca_core.models.golden_set import GoldenLabels, GoldenSample

ROOT = Path(__file__).resolve().parents[2]


def load(name: str) -> Any:
    spec = importlib.util.spec_from_file_location(
        f"golden_{name}", ROOT / "scripts/golden" / f"{name}.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


sampler = load("sample")
annotate = load("annotate")

URL = "https://github.com/acme/app"
COMMIT = "c" * 40
CONFIG = json.loads((ROOT / "golden-set/sampling.json").read_text(encoding="utf-8"))
HOSTILE = '<img src=x onerror="alert(1)">'


def finding(n: int, **over: Any) -> dict[str, Any]:
    location = {"path": over.pop("path", f"app/m{n}.py"), "start_line": over.pop("line", 3)}
    return {
        "fingerprint": f"sha256:{n:064x}", "category": "sast", "tool": "bandit",
        "rule_id": "B608", "message": f"messaggio {n}", "location": location, **over,
    }  # fmt: skip


def report(findings: list[dict[str, Any]], commit: str = COMMIT, semgrep: str = "ok") -> dict:
    plugins = [{"name": "semgrep", "outcome": semgrep}]
    return {"repository": {"commit": commit}, "plugins": plugins, "findings": findings}


def test_only_judgeable_python_sast_findings_are_candidates() -> None:
    findings = [
        finding(1),
        finding(2, category="quality"),
        finding(3, path="web/a.ts"),
        finding(4, rule_id="B101"),
        finding(5, rule_id="B105"),
        finding(6, rule_id="B404"),
        finding(7, path="tests/test_a.py"),
        finding(8, path="app/vendor/lib.py"),
        finding(9, line=None),
    ]
    found, warnings = sampler.candidates([report(findings)], {COMMIT: URL}, CONFIG)
    assert [f["fingerprint"] for f in found] == [finding(1)["fingerprint"]]
    assert warnings == []


def test_a_failed_sast_plugin_is_reported_and_an_unknown_commit_refused() -> None:
    _, warnings = sampler.candidates([report([], semgrep="failed")], {COMMIT: URL}, CONFIG)
    assert len(warnings) == 1
    with pytest.raises(ValueError, match="non è di un repository del corpus"):
        sampler.candidates([report([], commit="d" * 40)], {COMMIT: URL}, CONFIG)


def candidates_of(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sampler.candidates([report(findings)], {COMMIT: URL}, CONFIG)[0]


def test_one_point_per_line_and_a_cap_per_repository_and_rule() -> None:
    same_line = [finding(1, path="a.py"), finding(2, path="a.py", rule_id="B703")]
    many = [finding(n) for n in range(10, 40)]
    kept = sampler.pool(candidates_of(same_line + many), "s", cap=5)
    assert len({(i["path"], i["start_line"]) for i in kept}) == len(kept)
    assert sum(i["rule_id"] == "B608" for i in kept) == 5


def test_the_draw_does_not_depend_on_report_order_and_skips_used_points() -> None:
    found = candidates_of([finding(n) for n in range(1, 30)])
    first, messages = sampler.draw(found, CONFIG, name="pilota", size=5, seed="s")
    again, _ = sampler.draw(found[::-1], CONFIG, name="pilota", size=5, seed="s")
    assert first == again
    assert len(messages) == 5
    used = [i.model_dump() for i in first.items]
    other, _ = sampler.draw(found, CONFIG, name="test", size=5, seed="s", used=used)
    assert not {i.path for i in first.items} & {i.path for i in other.items}
    with pytest.raises(ValueError, match="ne servono"):
        sampler.draw(found, CONFIG, name="test", size=25, seed="s", used=used)


def test_the_sample_holds_references_only() -> None:
    sample, _ = sampler.draw(
        candidates_of([finding(1, message=HOSTILE)]), CONFIG, name="pilota", size=1, seed="s"
    )
    assert HOSTILE not in sample.model_dump_json()
    assert "messaggio" not in sample.model_dump_json()


def test_the_committed_files_are_consistent() -> None:
    corpus = json.loads((ROOT / "golden-set/corpus.json").read_text())["repositories"]
    commits = {r["url"]: r["commit"] for r in corpus}
    assert len(commits) == 30
    for path in (ROOT / "golden-set").glob("*.sample.json"):
        sample = GoldenSample.model_validate_json(path.read_bytes())
        assert path.name == f"{sample.set}.sample.json"
        assert all(commits[i.repository] == i.commit for i in sample.items)
        assert len({(i.repository, i.path, i.start_line) for i in sample.items}) == len(
            sample.items
        )
    for path in (ROOT / "golden-set").glob("*.labels.*.json"):
        labels = GoldenLabels.model_validate_json(path.read_bytes())
        assert (path.parent / f"{labels.set}.sample.json").is_file()


# --- annotazione --------------------------------------------------------------------------------


def git(folder: Path, *arguments: str) -> str:
    identity = ["-c", "user.name=t", "-c", "user.email=t@example.invalid"]
    return subprocess.run(
        ["git", "-C", str(folder), *identity, *arguments],
        capture_output=True,
        check=True,
        text=True,
    ).stdout.strip()


@pytest.fixture
def work(tmp_path: Path) -> tuple[Path, Path]:
    """Un campione di due voci con la sua copia di codice. Restituisce campione e materiale."""
    clone = tmp_path / "materials/repos/acme__app"
    clone.mkdir(parents=True)
    git(clone, "init", "-q")
    (clone / "app.py").write_text("\n".join(f"line {n} {HOSTILE}" for n in range(1, 301)))
    git(clone, "add", ".")
    git(clone, "commit", "-qm", "x", "--no-verify")
    commit = git(clone, "rev-parse", "HEAD")
    found = sampler.candidates(
        [report([finding(1, path="app.py", line=50), finding(2, path="app.py", line=90)], commit)],
        {commit: URL},
        CONFIG,
    )[0]
    sample, messages = sampler.draw(found, CONFIG, name="pilota", size=2, seed="s")
    target = tmp_path / "golden-set/pilota.sample.json"
    target.parent.mkdir()
    target.write_text(sample.model_dump_json())
    (tmp_path / "materials/messaggi-pilota.json").write_text(json.dumps(messages))
    return target, tmp_path / "materials"


def annotation(work: tuple[Path, Path]) -> Any:
    return annotate.Annotation(*work, "annotatore-1")


def test_the_view_shows_no_level_and_the_code_comes_from_the_commit(work: tuple) -> None:
    tool = annotation(work)
    view = tool.view()
    assert not {"level", "score", "severity"} & set(view["items"][0])
    assert view["items"][0]["message"].startswith("messaggio")
    clone = tool.clones / "acme__app"
    (clone / "app.py").write_text("cambiato dopo")
    block = tool.evidence(1)["blocks"][0]
    line = view["items"][0]["line"]
    assert block["highlight"] == line
    assert block["lines"][line - block["start"]] == f"line {line} {HOSTILE}"
    assert len(tool.evidence(1, "full")["blocks"][0]["lines"]) == 300


def test_missing_code_is_said_not_invented(work: tuple) -> None:
    tool = annotation(work)
    tool.clones = tool.clones / "altrove"
    assert tool.evidence(1)["blocks"] == []
    with pytest.raises(annotate.AnnotationError):
        tool.evidence(3)


def test_saving_keeps_progress_and_refuses_a_stale_page(work: tuple) -> None:
    tool = annotation(work)
    assert tool.save(1, {"revision": 0, "label": "vero", "seconds": 30}) == {"revision": 1}
    tool.save(1, {"revision": 1, "label": "non-so", "note": "dubbio", "seconds": 5})
    state = annotation(work).state()
    assert (state["labels"], state["notes"], state["seconds"]) == (
        {"1": "non-so"},
        {"1": "dubbio"},
        {"1": 35},
    )
    with pytest.raises(annotate.AnnotationError, match="altrove"):
        tool.save(2, {"revision": 1, "label": "vero"})
    tool.save(1, {"revision": 2, "label": None})
    assert tool.state()["labels"] == {}


@pytest.mark.parametrize(
    "body",
    [
        {"label": "forse"},
        {"seconds": -1},
        {"seconds": True},
        {"seconds": 999999},
        {"note": "x" * 1001},
    ],
)
def test_invalid_values_are_refused(work: tuple, body: dict) -> None:
    with pytest.raises(annotate.AnnotationError):
        annotation(work).save(1, {"revision": 0, **body})


def test_a_changed_sample_invalidates_the_progress(work: tuple) -> None:
    annotation(work).save(1, {"revision": 0, "label": "vero"})
    work[0].write_text(work[0].read_text() + "\n")
    with pytest.raises(annotate.AnnotationError, match="altro campione"):
        annotation(work).state()


def test_delivery_is_complete_final_and_without_notes(work: tuple) -> None:
    tool = annotation(work)
    tool.save(1, {"revision": 0, "label": "vero", "note": "nota privata", "seconds": 12})
    with pytest.raises(annotate.AnnotationError, match="mancano 1"):
        tool.deliver(1)
    tool.save(2, {"revision": 1, "label": "falso-positivo"})
    with pytest.raises(annotate.AnnotationError, match="altrove"):
        tool.deliver(1)
    done = tool.deliver(2)
    assert done["counts"] == {"vero": 1, "falso-positivo": 1}
    text = tool.target.read_text()
    labels = GoldenLabels.model_validate_json(text)
    assert [(x.label, x.seconds) for x in labels.labels] == [("vero", 12), ("falso-positivo", 0)]
    assert labels.sample_sha256 == tool.digest
    assert "nota privata" not in text and HOSTILE not in text
    for call in (lambda: tool.deliver(2), lambda: tool.save(1, {"revision": 2, "label": None})):
        with pytest.raises(annotate.AnnotationError, match="non si modifica"):
            call()


def test_a_second_round_does_not_see_the_first(work: tuple) -> None:
    annotation(work).save(1, {"revision": 0, "label": "vero"})
    second = annotate.Annotation(*work, "annotatore-1", 2)
    assert second.state()["labels"] == {}


@pytest.fixture
def server(work: tuple) -> Iterator[str]:
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), annotate.make_handler(annotation(work), "s3gr3t"))
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()
    httpd.server_close()


def call(url: str, method: str = "GET", body: bytes | None = None, **headers: str) -> tuple:
    request = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request) as response:
            return response.status, response.read(), response.headers
    except urllib.error.HTTPError as error:
        return error.code, error.read(), error.headers


def test_the_api_needs_the_secret_and_a_local_host(server: str) -> None:
    assert call(f"{server}/api/sample")[0] == 403
    assert call(f"{server}/api/sample", **{"X-Token": "altro"})[0] == 403
    assert call(f"{server}/", Host="evil.example")[0] == 403
    status, body, _ = call(f"{server}/api/sample", **{"X-Token": "s3gr3t"})
    assert status == 200 and len(json.loads(body)["items"]) == 2


def test_pages_are_served_with_a_closed_policy_and_nothing_else(server: str) -> None:
    for path in ("/", "/app.js", "/style.css"):
        status, _, headers = call(server + path)
        assert status == 200 and "default-src 'none'" in headers["Content-Security-Policy"]
    assert call(f"{server}/annotate.py")[0] == 404
    assert call(f"{server}/../sample.py")[0] == 404


def test_saving_and_delivering_over_http(server: str) -> None:
    token = {"X-Token": "s3gr3t"}
    for n, revision in ((1, 0), (2, 1)):
        body = json.dumps({"revision": revision, "label": "vero"}).encode()
        assert call(f"{server}/api/item/{n}", "PUT", body, **token)[0] == 200
    assert call(f"{server}/api/item/1", "PUT", b"{", **token)[0] == 400
    assert call(f"{server}/api/item/1", "PUT", b"[]", **token)[0] == 400
    status, body, _ = call(f"{server}/api/deliver", "POST", b'{"revision": 2}', **token)
    assert status == 200 and json.loads(body)["counts"] == {"vero": 2}


def test_the_page_never_writes_html() -> None:
    script = (ROOT / "scripts/golden/annotate_ui/app.js").read_text()
    for forbidden in ("innerHTML", "insertAdjacentHTML", "outerHTML", "document.write", "eval("):
        assert forbidden not in script

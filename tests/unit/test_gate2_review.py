"""La dashboard di valutazione di X-04: cieca per costruzione, ordinamento corretto, consegna che
non si modifica, server solo locale. Dati finti."""

import csv
import importlib.util
import json
import random
import shutil
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

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts/gate2"


def load(name: str) -> Any:
    spec = importlib.util.spec_from_file_location(f"gate2_{name}", SCRIPTS / f"{name}.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


review_tool = load("review")
gate2 = load("gate2")

HOSTILE = '<img src=x onerror="alert(1)">'


def finding(n: int, **over: Any) -> dict[str, Any]:
    return {
        "fingerprint": f"sha256:{n:064x}", "category": "quality", "rule_id": f"R{n}",
        "title": f"Problema {n}", "message": f"messaggio {n}", "level": "critico",
        "location": {"path": "app/a.py", "start_line": 40}, "tools": ["ruff"], **over,
    }  # fmt: skip


def repository(root: Path, files: dict[str, str]) -> tuple[Path, str]:
    root.mkdir()
    for path, text in files.items():
        (root / path).parent.mkdir(parents=True, exist_ok=True)
        (root / path).write_text(text)
    identity = ["-c", "user.name=t", "-c", "user.email=t@example.invalid"]
    for args in (["init", "-q"], ["add", "-A"], [*identity, "commit", "-qm", "x"]):
        subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)
    head = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"], check=True, capture_output=True, text=True
    )
    return root, head.stdout.strip()


@pytest.fixture
def setup(tmp_path: Path) -> Any:
    """Materiale scritto dallo strumento vero di X-03, più un repository con il codice."""
    code = "".join(f"riga {i}\n" for i in range(1, 101))
    repo = repository(tmp_path / "repo", {"app/a.py": code, "requirements.txt": "x==1\nlodash\n"})
    findings = [
        finding(1, title=HOSTILE, message="prima riga\nseconda riga"),
        finding(2, location={"path": "requirements.txt"}, category="dependency",
                message="Package 'lodash@1.0' is vulnerable to 'CVE-0'"),
        finding(3, location={"path": "../fuori.txt"}),
        finding(4),
        finding(5),
    ]  # fmt: skip
    materials = tmp_path / "material"
    sample = gate2.make_sample({"findings": findings}, 1, 30)
    gate2.write_sample(sample, materials, "demo")
    return review_tool.Review(materials, {"demo": repo}), materials


def number_of(tool: Any, rule: str) -> int:
    return next(i["n"] for i in tool.items("demo") if i["rule"] == rule)


def classify(tool: Any, buckets: dict[int, int], **over: Any) -> None:
    tool.save("demo", {"buckets": buckets, "revision": tool.load("demo")[1], **over})


def deliver(tool: Any) -> Any:
    """Come fa la pagina: si consegna il riepilogo che si è visto."""
    shown = tool.preview("demo")
    return tool.deliver("demo", shown["revision"], shown["sha256"])


def test_the_sample_written_by_x03_is_read_back_with_every_field(setup: Any) -> None:
    tool, _ = setup
    items = tool.items("demo")
    assert [i["n"] for i in items] == [1, 2, 3, 4, 5]
    hostile = next(i for i in items if i["rule"] == "R1")
    assert hostile["title"] == HOSTILE and hostile["message"] == "prima riga\nseconda riga"
    assert hostile["position"] == "app/a.py:40" and hostile["category"] == "quality"


def test_it_never_reads_the_report_the_key_or_another_ranking(setup: Any) -> None:
    """Cieca per costruzione: con quei file illeggibili (qui: cartelle) funziona tutto."""
    tool, materials = setup
    (materials / "chiave-demo.json").unlink()
    for name in ("chiave-demo.json", "report-demo.json", "ordinamento-demo-claude.csv"):
        (materials / name).mkdir()
    assert tool.summary() == [{"name": "demo", "total": 5, "assigned": 0, "delivered": False}]
    for item in tool.items("demo"):
        tool.evidence("demo", item["n"])
    classify(tool, dict.fromkeys(range(1, 6), 2))
    deliver(tool)


def test_a_ranking_already_in_the_csv_is_not_loaded_and_is_kept_as_a_copy(setup: Any) -> None:
    tool, materials = setup
    old = "n,rank\n" + "".join(f"{n},{n}\n" for n in range(1, 6))
    (materials / "ordinamento-demo.csv").write_text(old)
    assert tool.load("demo")[0]["buckets"] == {}
    classify(tool, dict.fromkeys(range(1, 6), 1))
    record = deliver(tool)
    assert (materials / record["previous"]).read_text() == old


def test_an_empty_template_leaves_no_copy(setup: Any) -> None:
    tool, _ = setup
    classify(tool, dict.fromkeys(range(1, 6), 1))
    assert deliver(tool)["previous"] is None


def test_groups_give_the_ranks_and_an_untouched_group_is_all_tied(setup: Any) -> None:
    tool, materials = setup
    classify(tool, {5: 1, 2: 1, 4: 2, 1: 3, 3: 3})
    record = deliver(tool)
    rows = {int(r["n"]): int(r["rank"]) for r in
            csv.DictReader((materials / "ordinamento-demo.csv").open())}  # fmt: skip
    assert rows == {2: 1, 5: 1, 4: 3, 1: 4, 3: 4}
    assert gate2.read_ranking(materials / "ordinamento-demo.csv") == rows
    assert json.loads((materials / "consegna-demo.json").read_text()) == record


def test_a_tier_moves_only_the_chosen_finding() -> None:
    """Portare uno in cima non ordina gli altri fra loro."""
    state = {"buckets": dict.fromkeys(["1", "2", "3", "4"], 1) | {"5": 4},
             "tiers": {"3": -1, "2": 1}, "notes": {}}  # fmt: skip
    assert review_tool.ranks(state, 5) == {3: 1, 1: 2, 4: 2, 2: 4, 5: 5}


def test_ranks_come_only_from_group_and_tier() -> None:
    rng = random.Random(7)  # noqa: S311
    for _ in range(200):
        buckets = {str(n): rng.randint(1, 4) for n in range(1, 31)}
        tiers = {str(n): rng.randint(-2, 2) for n in rng.sample(range(1, 31), 12)}
        out = review_tool.ranks({"buckets": buckets, "tiers": tiers, "notes": {}}, 30)
        assert sorted(out) == list(range(1, 31)) and min(out.values()) == 1
        key = {n: (buckets[str(n)], tiers.get(str(n), 0)) for n in out}
        for a in out:
            for b in out:
                assert (out[a] < out[b]) == (key[a] < key[b])
                assert (out[a] == out[b]) == (key[a] == key[b])


def test_delivery_needs_every_finding_and_then_nothing_changes(setup: Any) -> None:
    tool, materials = setup
    classify(tool, {1: 1, 2: 2})
    with pytest.raises(review_tool.ReviewError, match="mancano 3"):
        tool.preview("demo")
    classify(tool, dict.fromkeys(range(1, 6), 1))
    shown = tool.preview("demo")
    deliver(tool)
    delivered = (materials / "ordinamento-demo.csv").read_bytes()
    assert delivered.decode() == shown["csv"]
    for action in (lambda: classify(tool, dict.fromkeys(range(1, 6), 2)),
                   lambda: tool.deliver("demo", shown["revision"], shown["sha256"])):  # fmt: skip
        with pytest.raises(review_tool.ReviewError, match="già consegnato"):
            action()
    assert (materials / "ordinamento-demo.csv").read_bytes() == delivered


def test_a_second_tab_cannot_overwrite_in_silence(setup: Any) -> None:
    tool, _ = setup
    first = {"buckets": {"1": 1, "2": 1}, "revision": 0}
    assert tool.save("demo", first) == {"revision": 1}
    for stale in (0, 2, None, "1"):
        with pytest.raises(review_tool.ReviewError, match="altrove") as refused:
            tool.save("demo", {"buckets": {"1": 4}, "revision": stale})
        assert refused.value.status == 409
    assert tool.load("demo")[0]["buckets"] == {"1": 1, "2": 1}


def test_only_the_summary_that_was_seen_can_be_delivered(setup: Any) -> None:
    """Il difetto trovato dalla revisione: la consegna scriveva uno stato diverso da quello a
    schermo."""
    tool, materials = setup
    classify(tool, dict.fromkeys(range(1, 6), 2))
    seen = tool.preview("demo")
    classify(tool, dict.fromkeys(range(1, 6), 2) | {3: 1})
    now = tool.preview("demo")
    for revision, sha256 in ((seen["revision"], seen["sha256"]), (now["revision"], seen["sha256"]),
                             (seen["revision"], now["sha256"]), (None, None)):  # fmt: skip
        with pytest.raises(review_tool.ReviewError, match="cambiato"):
            tool.deliver("demo", revision, sha256)
    assert not (materials / "consegna-demo.json").exists()
    tool.deliver("demo", now["revision"], now["sha256"])


def test_progress_in_the_old_format_loses_its_order(setup: Any) -> None:
    tool, materials = setup
    old = {"buckets": {"1": 1}, "ordered": {"1": [1]}, "tied": [1], "notes": {}}
    (materials / "progresso-demo.json").write_text(json.dumps(old))
    assert tool.load("demo") == ({"buckets": {"1": 1}, "tiers": {}, "notes": {}}, 0)


def test_a_tier_without_a_group_or_equal_to_zero_is_dropped() -> None:
    state = review_tool.clean_state({"buckets": {"1": 1, "2": 1}, "tiers": {"1": 0, "3": -1}}, 5)
    assert state["tiers"] == {}


@pytest.mark.parametrize(
    "raw",
    [
        [], {"buckets": {"1": 5}}, {"buckets": {"1": True}}, {"buckets": {"9": 1}},
        {"buckets": {"x": 1}}, {"tiers": {"1": 101}}, {"tiers": {"1": 0.5}},
        {"tiers": {"1": True}}, {"notes": {"1": "x" * 1001}},
    ],
)  # fmt: skip
def test_a_malformed_state_is_refused(raw: Any) -> None:
    with pytest.raises(review_tool.ReviewError):
        review_tool.clean_state(raw, 5)


BANDS = SCRIPTS / "review_ui/bands.js"
NODE = shutil.which("node")

BANDS_CHECK = """
const Bands = require(process.argv[1]);
let seed = 7;
const random = (n) => { seed = (seed * 48271) % 2147483647; return seed % n; };
const members = [1, 2, 3, 4, 5, 6, 7, 8];
const fail = (why) => { console.log(why); process.exit(1); };
const order = (tiers, a, b) => Math.sign((tiers[a] ?? 0) - (tiers[b] ?? 0));
let tiers = {};
for (let step = 0; step < 5000; step++) {
  const n = members[random(8)], action = ["top", "bottom", "up", "down", "reset"][random(5)];
  const next = Bands.move(members, tiers, n, action);
  // gli altri restano fra loro come erano: nessun giudizio inventato
  for (const a of members) for (const b of members)
    if (a !== n && b !== n && order(tiers, a, b) !== order(next, a, b)) fail(`altri ${action}`);
  for (const v of Object.values(next))
    if (!Number.isInteger(v) || v === 0 || Math.abs(v) > 8) fail("fascia " + v);
  const bands = Bands.bandsOf(members, next).map((b) => b.ids);
  if (action === "top" && !(bands[0].length === 1 && bands[0][0] === n)) fail("top");
  if (action === "bottom" && !(bands.at(-1).length === 1 && bands.at(-1)[0] === n)) fail("bottom");
  if (action === "reset" && (next[n] ?? 0) !== 0) fail("reset");
  tiers = next;
}
const all = [1, 2, 3];
const split = Bands.move(all, {}, 2, "up");
const shape = (t) => JSON.stringify(Bands.bandsOf(all, t).map((b) => b.ids));
if (shape(split) !== "[[2],[1,3]]") fail("esce sopra " + shape(split));
if (shape(Bands.move(all, split, 2, "down")) !== "[[1,2,3]]") fail("torna pari");
if (Bands.canMove(all, split, 2, "up") || Bands.canMove(all, split, 2, "top")) fail("già in cima");
if (Bands.canMove([1], {}, 1, "up")) fail("da solo nel gruppo");
console.log("ok");
"""


@pytest.mark.skipif(NODE is None, reason="serve Node")
def test_moving_a_finding_never_reorders_the_others() -> None:
    assert NODE is not None
    done = subprocess.run(  # noqa: S603
        [NODE, "-e", BANDS_CHECK, str(BANDS)], capture_output=True, text=True, timeout=60
    )
    assert done.returncode == 0, done.stdout + done.stderr


def test_the_evidence_is_the_code_at_the_pinned_commit(setup: Any) -> None:
    tool, materials = setup
    (tool.sources["demo"][0] / "app/a.py").write_text("modificato dopo\n")
    [block] = tool.evidence("demo", number_of(tool, "R4"))["blocks"]
    assert (block["start"], block["highlight"], block["lines"][10]) == (30, 40, "riga 40")
    [wide] = tool.evidence("demo", number_of(tool, "R4"), view="wide")["blocks"]
    assert len(wide["lines"]) > len(block["lines"])


def test_a_dependency_shows_the_lines_that_name_the_package(setup: Any) -> None:
    tool, _ = setup
    found = tool.evidence("demo", number_of(tool, "R2"))
    assert "1 punti su 1 che nominano «lodash»" in found["note"]
    assert found["blocks"][0]["highlight"] == 2


def test_the_lines_near_the_reported_version_come_first_and_the_cut_is_declared() -> None:
    lines = [f'dep = "pkg" # {i}' for i in range(1, 11)]
    lines += ['name = "pkg-extra"', "pkg.js", 'name = "pkg"', 'version = "9.9"']
    spans, [note] = review_tool._spans(lines, None, "Package 'pkg@9.9' is vulnerable", "normal")
    marked = [mark for _, _, mark in spans]
    # 11 righe nominano il pacchetto (non `pkg-extra` né `pkg.js`): se ne mostrano 6, tra cui
    # quella accanto alla versione, che per posizione resterebbe fuori
    assert len(marked) == 6 and 13 in marked
    assert note.startswith("Mostrati 6 punti su 11") and "9.9" in note


def test_a_line_past_the_end_of_the_file_is_declared(setup: Any) -> None:
    tool, _ = setup
    lines = [str(i) for i in range(1, 11)]
    spans, [note] = review_tool._spans(lines, 99, "", "normal")
    assert "oltre la fine" in note and spans[0][2] is None
    whole, _ = review_tool._spans(lines, 5, "", "full")
    assert whole == [(1, 10, 5)]


def test_a_path_outside_the_repository_gives_no_code(setup: Any) -> None:
    tool, materials = setup
    (materials.parent / "fuori.txt").write_text("segreto")
    found = tool.evidence("demo", number_of(tool, "R3"))
    assert found["blocks"] == [] and "segreto" not in json.dumps(found)


def test_the_commits_come_from_the_protocol_table() -> None:
    commits = review_tool.protocol_commits(review_tool.PROTOCOL.read_text())
    # solo la tabella dei repository del gate, non quella delle PR di riferimento di X-05
    assert set(commits) == {"orario-scuola", "birds-cataloger", "school-planner"}


def test_the_materials_stay_outside_the_repository() -> None:
    assert review_tool.main(["--materials", str(SCRIPTS.parents[1] / "x")]) == 2


@pytest.fixture
def server(setup: Any) -> Iterator[str]:
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), review_tool.make_handler(setup[0], "segreto"))
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()
    httpd.server_close()


def call(url: str, method: str = "GET", body: bytes | None = None, **headers: str) -> Any:
    request = urllib.request.Request(url, data=body, method=method, headers=headers)  # noqa: S310
    try:
        with urllib.request.urlopen(request, timeout=10) as reply:  # noqa: S310
            return reply.status, reply.read(), dict(reply.headers)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), dict(exc.headers)


def test_the_api_needs_the_secret_and_the_local_host_name(server: str) -> None:
    assert call(server + "/api/repos")[0] == 403
    assert call(server + "/api/repos", **{"X-Token": "altro"})[0] == 403
    assert call(server + "/api/repos", **{"X-Token": "segreto", "Host": "evil.example"})[0] == 403
    assert call(server + "/", Host="evil.example")[0] == 403
    status, body, headers = call(server + "/api/repos", **{"X-Token": "segreto"})
    assert status == 200 and json.loads(body)[0]["name"] == "demo"
    assert "default-src 'none'" in headers["Content-Security-Policy"]
    assert headers["Cache-Control"] == "no-store"


def test_only_the_page_files_are_served(server: str) -> None:
    for path in ("/", "/app.js", "/bands.js", "/style.css"):
        assert call(server + path)[0] == 200, path
    for path in ("/review.py", "/../review.py", "/review_ui/app.js"):
        assert call(server + path)[0] == 404, path
    token = {"X-Token": "segreto"}
    for path in ("/api/repo/altro", "/api/repo/..%2Fx", "/api/evidence/demo/99", "/api/nulla"):
        assert call(server + path, **token)[0] == 404, path


def test_saving_and_delivering_through_the_api(server: str) -> None:
    token = {"X-Token": "segreto"}

    def send(path: str, method: str, body: Any) -> Any:
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        return call(server + path, method, data, **token)

    state = {"buckets": dict.fromkeys("12345", 3), "revision": 0}
    assert send("/api/state/demo", "PUT", state)[0] == 200
    assert send("/api/state/demo", "PUT", state)[0] == 409  # revisione superata
    assert send("/api/state/demo", "PUT", b"x" * 70_000)[0] == 413
    assert send("/api/state/demo", "PUT", b"{")[0] == 400
    assert send("/api/state/demo", "PUT", [1])[0] == 400
    assert send("/api/state/demo", "PUT", {"buckets": 3, "revision": 1})[0] == 400
    assert send("/api/deliver/demo", "POST", {"revision": 1, "sha256": "altra"})[0] == 409
    status, body, _ = call(server + "/api/preview/demo", **token)
    shown = json.loads(body)
    assert status == 200
    seen = {k: shown[k] for k in ("revision", "sha256")}
    assert send("/api/deliver/demo", "POST", seen)[0] == 200
    assert send("/api/state/demo", "PUT", state | {"revision": 1})[0] == 409


def test_the_page_never_builds_markup_from_data() -> None:
    script = "".join(p.read_text() for p in sorted((SCRIPTS / "review_ui").glob("*.js")))
    for forbidden in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("):
        assert forbidden not in script, forbidden
    page = (SCRIPTS / "review_ui/index.html").read_text()
    assert "http://" not in page and "https://" not in page

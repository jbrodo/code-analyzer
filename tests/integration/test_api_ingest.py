"""B-03: l'ingestione di una scansione su PostgreSQL vero e un archivio su file system.

`CA_TEST_DOCKER=1`. Emittente OIDC finto in processo, nessuna rete esterna.
"""

import hashlib
import json
import os
import sys
import threading
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine, func, select
from starlette.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "unit"), str(ROOT / "unit" / "api")]
from apiauth import GITHUB_IDP, USER_IDP  # noqa: E402
from builders import finding, report  # noqa: E402
from idp import build, pipeline_issuer, user_issuer  # noqa: E402

from ca_api.app import create_app  # noqa: E402
from ca_api.config import Settings  # noqa: E402
from ca_api.db import migrate, stores  # noqa: E402
from ca_api.db.engine import make_engine, tenant_session  # noqa: E402
from ca_api.db.models import (  # noqa: E402
    Component,
    ExceptionRow,
    Finding,
    FindingEvent,
    FindingOccurrence,
    GraphEdge,
    GraphNode,
    Repository,
    Scan,
)
from ca_api.storage.filesystem import FileSystemArtifactStore  # noqa: E402
from ca_core.fakes import FixedClock  # noqa: E402
from ca_core.models.finding import BaselineState, Category, Level  # noqa: E402

pytestmark = pytest.mark.skipif(
    os.environ.get("CA_TEST_DOCKER") != "1", reason="richiede Docker (CA_TEST_DOCKER=1)"
)
SHA = "a" * 40
T0 = datetime(2026, 11, 17, 12, 0, tzinfo=UTC)
FILES = {"report": "report.json"}


@pytest.fixture(scope="module")
def database() -> Iterator[Engine]:
    from testcontainers.community.postgres import PostgresContainer

    with PostgresContainer("postgres:16", driver="pg8000") as postgres:
        engine = make_engine(postgres.get_connection_url())
        migrate.upgrade_global(engine)
        yield engine
        engine.dispose()


class Env:
    def __init__(self, engine: Engine, tmp: Path, tenant: str, schema: str) -> None:
        self.engine, self.tenant, self.schema, self.tmp = engine, tenant, schema, tmp
        _, fetcher, _, verifier = build(user_issuer(), pipeline_issuer())
        fetcher.publish(USER_IDP.jwks_url, USER_IDP.jwk())
        fetcher.publish(GITHUB_IDP.jwks_url, GITHUB_IDP.jwk())
        self.store = FileSystemArtifactStore(tmp / "artifacts")
        self.settings = Settings(max_part_bytes=200_000, max_request_bytes=400_000)
        self.client = TestClient(
            create_app(
                self.settings,
                verifier=verifier,
                engine=engine,
                store=self.store,
                clock=FixedClock(T0),
            )
        )

    def token(
        self,
        *,
        repo_id: str = "9001",
        name: str = "acme/shop",
        ref: str = "refs/heads/main",
        sha: str | None = SHA,
        owner: str = "4242",
    ) -> dict[str, str]:
        claims: dict[str, Any] = {
            "repository": name,
            "repository_id": repo_id,
            "repository_owner_id": owner,
            "ref": ref,
        }
        if sha is not None:
            claims["sha"] = sha
        return {
            "Authorization": "Bearer "
            + GITHUB_IDP.sign(GITHUB_IDP.claims(subject="repo", **claims))
        }

    def post(self, body: bytes, *, headers: dict[str, str] | None = None, **extra: bytes):
        files = {"report": ("anything.json", body, "application/json")}
        files.update({k: (f"{k}.json", v, "application/json") for k, v in extra.items()})
        return self.client.post("/v1/scans", files=files, headers=headers or self.token())

    def count(self, model: Any) -> int:
        with tenant_session(self.engine, self.schema) as session:
            return int(session.scalar(select(func.count()).select_from(model)) or 0)

    def one(self, model: Any, **where: Any) -> Any:
        with tenant_session(self.engine, self.schema) as session:
            row = session.scalar(select(model).filter_by(**where))
            if row is not None:
                session.expunge(row)
            return row


_tenants = iter(range(10_000))


@pytest.fixture
def env(database: Engine, tmp_path: Path) -> Env:
    """Un tenant nuovo per ogni prova: le prove non si vedono tra loro."""
    name = f"acme-{next(_tenants)}"
    schema = stores.create_tenant(database, name).schema
    # il proprietario 4242 delle pipeline va al tenant di questa prova (non a un nome fisso)
    auth_env = Env(database, tmp_path, name, schema)
    _, fetcher, _, verifier = build(
        user_issuer(),
        pipeline_issuer().model_copy(update={"owners": {"4242": name}}),
    )
    fetcher.publish(USER_IDP.jwks_url, USER_IDP.jwk())
    fetcher.publish(GITHUB_IDP.jwks_url, GITHUB_IDP.jwk())
    auth_env.client = TestClient(
        create_app(
            auth_env.settings,
            verifier=verifier,
            engine=database,
            store=auth_env.store,
            clock=FixedClock(T0),
        )
    )
    return auth_env


def make_report(
    findings=None, *, started: datetime = T0, status: str = "complete", **kv: Any
) -> bytes:
    data = report(
        findings or [finding("a", level=Level.HIGH)],
        started_at=started,
        status=status,
        repository={"name": "shop", "commit": SHA, "history": "full"},
        **kv,
    )
    return data.model_dump_json().encode()


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --- prima ingestione e idempotenza --------------------------------------------------------


def test_first_upload_is_201_and_records_scan_findings_occurrences_and_artifacts(env: Env) -> None:
    body = make_report([finding("a", level=Level.HIGH), finding("b", level=Level.LOW)])
    response = env.post(body)
    assert response.status_code == 201, response.text
    scan_id = response.json()["id"]
    scan = env.one(Scan, id=__import__("uuid").UUID(scan_id))
    assert (scan.kind, scan.status, scan.commit, scan.ref) == (
        "full",
        "complete",
        SHA,
        "refs/heads/main",
    )
    assert scan.report_sha256 == digest(body) and scan.artifact_keys["report"]["sha256"] == digest(
        body
    )
    assert env.count(Finding) == 2 and env.count(FindingOccurrence) == 2
    assert env.store.exists(f"{env.schema}/{scan_id}/report")
    with env.store.open(f"{env.schema}/{scan_id}/report") as handle:
        assert handle.read() == body


def test_the_same_upload_twice_is_200_with_the_same_id_and_no_new_rows(env: Env) -> None:
    body = make_report()
    first = env.post(body)
    rows = (env.count(Scan), env.count(Finding), env.count(FindingOccurrence))
    again = env.post(body)
    assert (first.status_code, again.status_code) == (201, 200)
    assert again.json() == first.json()
    assert (env.count(Scan), env.count(Finding), env.count(FindingOccurrence)) == rows


def test_findings_get_first_seen_and_last_seen_from_the_scan_and_the_repository_is_created(
    env: Env,
) -> None:
    env.post(make_report())
    row = env.one(Finding, fingerprint=finding("a").fingerprint)
    assert row.first_seen == T0 and row.last_seen == T0 and row.status == "aperto"
    repo = env.one(Repository, external_id="9001")
    assert (repo.name, repo.provider, repo.default_branch) == ("acme/shop", "github", "main")
    assert repo.current_scan_id is not None and (repo.tier, repo.internet_facing) == (None, None)


def test_the_name_of_the_uploaded_file_never_reaches_the_storage(env: Env) -> None:
    env.client.post(
        "/v1/scans",
        files={"report": ("../../etc/passwd", make_report(), "application/json")},
        headers=env.token(),
    )
    keys = [
        p.relative_to(env.tmp / "artifacts").as_posix()
        for p in (env.tmp / "artifacts").rglob("*")
        if p.is_file()
    ]
    assert len(keys) == 1 and keys[0].startswith(env.schema + "/") and keys[0].endswith("/report")
    assert "passwd" not in keys[0]


def test_two_repositories_with_the_same_report_bytes_are_two_scans(env: Env) -> None:
    body = make_report()
    one = env.post(body, headers=env.token(repo_id="1"))
    two = env.post(body, headers=env.token(repo_id="2"))
    assert one.status_code == two.status_code == 201 and one.json() != two.json()
    assert env.count(Repository) == 2 and env.count(Scan) == 2


# --- artefatti -----------------------------------------------------------------------------


def valid_sarif() -> bytes:
    return json.dumps(
        {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "t"}}, "results": []}]}
    ).encode()


def valid_sbom() -> bytes:
    sbom = json.loads(Path("tests/fixtures/plugin-output/syft.cdx.json").read_text())
    return json.dumps(sbom).encode()


def valid_graph() -> bytes:
    graph = {
        "version": 1,
        "modules": [
            {"path": "a.py", "language": "python", "parse": "completa", "churn": 2},
            {"path": "b.py", "language": "python", "parse": "completa", "churn": 0},
        ],
        "edges": [{"source": "a.py", "target": "b.py", "imports": 1, "confidence": "dichiarato"}],
        "stats": {"files_parsed": 2},
        "history": {"status": "completa", "window_days": 90},
    }
    return json.dumps(graph).encode()


def test_all_four_artifacts_are_stored_and_components_and_graph_recorded(env: Env) -> None:
    response = env.post(make_report(), sarif=valid_sarif(), sbom=valid_sbom(), graph=valid_graph())
    assert response.status_code == 201, response.text
    scan = env.one(Scan, id=__import__("uuid").UUID(response.json()["id"]))
    assert set(scan.artifact_keys) == {"report", "sarif", "sbom", "graph"}
    assert env.count(Component) > 0 and env.count(GraphNode) == 2 and env.count(GraphEdge) == 1


def test_the_same_report_with_different_artifacts_is_409_and_nothing_changes(env: Env) -> None:
    body = make_report()
    assert env.post(body, sarif=valid_sarif()).status_code == 201
    for extra in ({}, {"sbom": valid_sbom()}, {"sarif": b'{"version":"2.1.0","runs":[]}'}):
        response = env.post(body, **extra)
        assert response.status_code == 409 and response.json()["code"] == "artifacts-conflict", (
            extra
        )
    assert env.count(Scan) == 1


@pytest.mark.parametrize(
    ("kind", "data"),
    [
        ("report", b"not json"),
        ("report", b"{}"),
        ("report", b'{"version": 1}'),
        ("report", b"[" * 5000),
        ("sarif", b"{"),
        ("sarif", b'{"version": "9"}'),
        ("sarif", b"[" * 5000),
        ("sbom", b'{"bomFormat": "CycloneDX"}'),
        ("sbom", b"{"),
        ("graph", b'{"version": 2}'),
        ("graph", b"{}"),
    ],
)
def test_an_invalid_artifact_rejects_the_whole_request_and_stores_nothing(
    env: Env, kind: str, data: bytes
) -> None:
    good = make_report()
    files: dict[str, bytes] = {"sarif": valid_sarif(), "sbom": valid_sbom(), "graph": valid_graph()}
    if kind == "report":
        response = env.post(data)
    else:
        files[kind] = data
        response = env.post(good, **files)
    assert response.status_code == 422, response.text
    body = response.json()
    assert body["code"] == "report-schema-invalid" and body["status"] == 422
    assert env.count(Scan) == 0 and env.count(Finding) == 0
    assert not [p for p in (env.tmp / "artifacts").rglob("*") if p.is_file()]


def test_an_error_names_the_place_never_the_received_value(env: Env) -> None:
    bad = json.loads(make_report())
    bad["findings"][0]["level"] = "valore-segreto-da-non-ripetere"
    response = env.post(json.dumps(bad).encode())
    assert response.status_code == 422
    assert "valore-segreto" not in response.text
    assert response.json()["errors"][0]["pointer"].startswith("/findings/0/level")


def test_a_report_without_a_commit_is_refused(env: Env) -> None:
    data = (
        report([finding("a")], repository={"name": "shop", "history": "absent"})
        .model_dump_json()
        .encode()
    )
    response = env.post(data)
    assert response.status_code == 422 and "commit" in response.json()["detail"]


# --- identità ------------------------------------------------------------------------------


def test_a_user_cannot_upload_and_no_token_is_401(env: Env) -> None:
    user = {"Authorization": "Bearer " + USER_IDP.sign(groups=["admins"])}
    assert env.post(make_report(), headers=user).status_code == 403
    assert (
        env.client.post(
            "/v1/scans", files={"report": ("r", make_report(), "application/json")}
        ).status_code
        == 401
    )
    assert env.count(Scan) == 0


@pytest.mark.parametrize(
    "headers",
    [{"name": "acme/another-repo"}, {"sha": "b" * 40}],
    ids=["other-repository-name", "other-commit"],
)
def test_the_report_must_match_the_repository_and_commit_of_the_token(
    env: Env, headers: dict[str, str]
) -> None:
    response = env.post(make_report(), headers=env.token(**headers))
    assert response.status_code == 403 and response.json()["code"] == "repository-mismatch"
    assert env.count(Scan) == 0


def test_a_token_without_a_sha_is_not_checked_against_the_commit(env: Env) -> None:
    assert env.post(make_report(), headers=env.token(sha=None)).status_code == 201


def test_an_owner_whose_tenant_does_not_exist_is_403(env: Env, database: Engine) -> None:
    _, fetcher, _, verifier = build(
        pipeline_issuer().model_copy(update={"owners": {"4242": "no-such-tenant"}})
    )
    fetcher.publish(GITHUB_IDP.jwks_url, GITHUB_IDP.jwk())
    client = TestClient(
        create_app(env.settings, verifier=verifier, engine=database, store=env.store)
    )
    response = client.post(
        "/v1/scans", files={"report": ("r", make_report(), "application/json")}, headers=env.token()
    )
    assert response.status_code == 403 and response.json()["code"] == "forbidden"


# --- limiti di dimensione ------------------------------------------------------------------


def test_a_request_over_the_limit_is_413_and_stops_reading(env: Env) -> None:
    response = env.post(make_report(), sarif=b"x" * 450_000)
    assert response.status_code == 413 and response.json()["code"] == "payload-too-large"
    assert env.count(Scan) == 0


def test_a_part_over_the_part_limit_is_413_even_inside_the_request_limit(env: Env) -> None:
    response = env.post(make_report(), sarif=b"x" * 250_000)
    assert response.status_code == 413
    assert env.count(Scan) == 0 and not [
        p for p in (env.tmp / "artifacts").rglob("*") if p.is_file()
    ]


def test_a_false_content_length_does_not_bypass_the_limit(env: Env) -> None:
    boundary = "xBOUNDARYx"
    body = (
        (
            f'--{boundary}\r\nContent-Disposition: form-data; name="report"; filename="r"\r\n'
            "Content-Type: application/json\r\n\r\n"
        ).encode()
        + b"x" * 450_000
        + f"\r\n--{boundary}--\r\n".encode()
    )
    response = env.client.post(
        "/v1/scans",
        content=body,
        headers={
            **env.token(),
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Content-Length": "100",
        },
    )
    assert response.status_code in {413, 400, 422}
    assert env.count(Scan) == 0


# --- stato del server (ADR-0018) -----------------------------------------------------------


def post_full(env: Env, findings, minutes: int, status: str = "complete", **extra: bytes):
    return env.post(
        make_report(findings, started=T0 + timedelta(minutes=minutes), status=status), **extra
    )


def row(env: Env, name: str) -> Any:
    return env.one(Finding, fingerprint=finding(name).fingerprint)


def test_a_later_full_scan_updates_last_seen_keeps_first_seen_and_resolves_what_is_gone(
    env: Env,
) -> None:
    post_full(env, [finding("a"), finding("b")], 0)
    post_full(env, [finding("a")], 10)
    a, b = row(env, "a"), row(env, "b")
    assert (a.first_seen, a.last_seen) == (T0, T0 + timedelta(minutes=10))
    assert b.status == "risolto" and b.last_seen == T0
    with tenant_session(env.engine, env.schema) as session:
        events = [
            (e.actor, e.action, e.from_state, e.to_state)
            for e in session.scalars(select(FindingEvent).where(FindingEvent.finding_id == b.id))
        ]
    assert events == [("code-analyzer", "resolved", "aperto", "risolto")]


def test_a_partial_scan_adds_and_updates_but_never_resolves(env: Env) -> None:
    post_full(env, [finding("a"), finding("b")], 0)
    post_full(env, [finding("a")], 10, status="partial")
    assert row(env, "b").status == "aperto"
    assert row(env, "a").last_seen == T0 + timedelta(minutes=10)


def test_a_resolved_finding_that_comes_back_is_reopened_with_an_event_and_keeps_first_seen(
    env: Env,
) -> None:
    post_full(env, [finding("a"), finding("b")], 0)
    post_full(env, [finding("a")], 10)
    post_full(env, [finding("a"), finding("b")], 20)
    b = row(env, "b")
    assert (b.status, b.first_seen, b.last_seen) == ("aperto", T0, T0 + timedelta(minutes=20))
    with tenant_session(env.engine, env.schema) as session:
        actions = [
            e.action
            for e in session.scalars(
                select(FindingEvent)
                .where(FindingEvent.finding_id == b.id)
                .order_by(FindingEvent.at)
            )
        ]
    assert sorted(actions) == ["reopened", "resolved"]


def test_a_triaged_state_is_never_overwritten_by_a_later_scan(env: Env) -> None:
    post_full(env, [finding("a")], 0)
    with tenant_session(env.engine, env.schema) as session:
        session.scalar(select(Finding)).status = "falso_positivo"
    post_full(env, [finding("a")], 10)
    assert row(env, "a").status == "falso_positivo"


def test_a_pr_scan_creates_occurrences_but_moves_neither_dates_nor_the_current_scan(
    env: Env,
) -> None:
    post_full(env, [finding("a")], 0)
    current = env.one(Repository, external_id="9001").current_scan_id
    pr = make_report(
        [
            finding("a", baseline_state=BaselineState.EXISTING),
            finding("new", baseline_state=BaselineState.NEW),
        ],
        started=T0 + timedelta(minutes=30),
        scan={"kind": "pr", "base_commit": "c" * 40, "pull_request": 7},
        baseline={
            "status": "valid",
            "commit": "c" * 40,
            "source": "ci-artifact",
            "new": 1,
            "existing": 1,
        },
    )
    response = env.post(pr, headers=env.token(ref="refs/pull/7/merge"))
    assert response.status_code == 201, response.text
    assert env.one(Repository, external_id="9001").current_scan_id == current
    a, new = row(env, "a"), row(env, "new")
    assert a.last_seen == T0  # la PR non sposta last_seen
    assert new.first_seen is None and new.last_seen is None  # visto solo in una PR
    scan = env.one(Scan, id=__import__("uuid").UUID(response.json()["id"]))
    assert (scan.kind, scan.pull_request, scan.base_commit) == ("pr", 7, "c" * 40)
    occurrence = env.one(FindingOccurrence, scan_id=scan.id, finding_id=new.id)
    assert occurrence.baseline_state == "new"


def test_a_full_scan_of_another_branch_does_not_become_the_current_one(env: Env) -> None:
    post_full(env, [finding("a")], 0)
    current = env.one(Repository, external_id="9001").current_scan_id
    env.post(
        make_report([finding("feat")], started=T0 + timedelta(minutes=5)),
        headers=env.token(ref="refs/heads/feature/x"),
    )
    assert env.one(Repository, external_id="9001").current_scan_id == current
    assert row(env, "feat").first_seen is None and row(env, "a").status == "aperto"


def test_a_late_report_is_recorded_without_changing_the_current_scan_or_states(env: Env) -> None:
    post_full(env, [finding("a")], 30)
    current = env.one(Repository, external_id="9001").current_scan_id
    response = post_full(env, [finding("late")], 0)
    assert response.status_code == 201
    assert env.one(Repository, external_id="9001").current_scan_id == current
    assert row(env, "a").status == "aperto" and row(env, "late").first_seen is None


def test_components_and_graph_follow_the_current_scan(env: Env) -> None:
    post_full(env, [finding("a")], 0, sbom=valid_sbom(), graph=valid_graph())
    first = (env.count(Component), env.count(GraphNode), env.count(GraphEdge))
    assert first[0] > 0 and first[1:] == (2, 1)
    post_full(env, [finding("a")], 10, graph=valid_graph())
    assert (env.count(Component), env.count(GraphNode), env.count(GraphEdge)) == (
        0,
        2,
        1,
    )  # sostituiti


def test_the_exceptions_of_the_repository_are_stored_as_unverified_declarations(env: Env) -> None:
    f = finding("a")
    data = json.loads(make_report([f]))
    data["exceptions"] = [
        {
            "fingerprint": f.fingerprint,
            "reason": "migrazione in corso",
            "expires": "2027-06-30",
            "approved_by": "Chiunque",
        }
    ]
    assert env.post(json.dumps(data).encode()).status_code == 201
    exception = env.one(ExceptionRow, origin="repository")
    assert (exception.approved_by, exception.approved_by_verified) == ("Chiunque", False)


def test_scores_and_levels_are_recorded_per_occurrence(env: Env) -> None:
    f = finding("a", category=Category.SAST, level=Level.HIGH).model_copy(update={"score": 49.0})
    assert env.post(make_report([f])).status_code == 201
    occurrence = env.one(FindingOccurrence)
    assert occurrence.level == "alto" and occurrence.report_status == "aperto"


# --- fallimenti e corse --------------------------------------------------------------------


def test_a_database_failure_leaves_no_orphan_objects(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    import ca_api.ingest as ingest_module

    def boom(*_: Any, **__: Any) -> None:
        raise RuntimeError("guasto simulato")

    monkeypatch.setattr(ingest_module, "_record", boom)
    client = TestClient(env.client.app, raise_server_exceptions=False)
    response = client.post(
        "/v1/scans", files={"report": ("r", make_report(), "application/json")}, headers=env.token()
    )
    assert response.status_code == 500
    assert env.count(Scan) == 0
    assert not [p for p in (env.tmp / "artifacts").rglob("*") if p.is_file()]


def test_the_same_run_sent_twice_at_once_gives_one_scan(env: Env) -> None:
    body = make_report([finding(str(i)) for i in range(30)])
    statuses: list[int] = []

    def send() -> None:
        statuses.append(env.post(body).status_code)

    threads = [threading.Thread(target=send) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(statuses).count(201) == 1 and set(statuses) <= {200, 201}
    assert env.count(Scan) == 1 and env.count(Finding) == 30 and env.count(FindingOccurrence) == 30


def test_the_status_and_error_format_are_always_the_single_problem_json(env: Env) -> None:
    for response in (env.post(b"x"), env.client.post("/v1/scans")):
        assert response.headers["content-type"].startswith("application/problem+json")


def test_manage_creates_a_tenant_and_migrates_without_echoing_the_connection_string(
    database: Engine, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from ca_api.manage import main

    url = database.url.render_as_string(hide_password=False)
    monkeypatch.setenv("CA_API_DATABASE_URL", url)
    assert main(["create-tenant", "managed"]) == 0
    assert main(["migrate"]) == 0
    monkeypatch.setenv("CA_API_DATABASE_URL", "postgresql+pg8000://u:topsecret@127.0.0.1:1/x")
    assert main(["migrate"]) == 2
    captured = capsys.readouterr()
    assert "topsecret" not in captured.out + captured.err

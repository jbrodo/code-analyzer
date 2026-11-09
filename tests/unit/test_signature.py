"""R-04: verifica della firma con un `cosign` finto (script) e runtime OCI finti."""

import json
import stat
from pathlib import Path

import pytest

from ca_core.models import PackagedPluginManifest
from ca_core.ports import PluginRunRequest, RunOutcome, ScanAborted, Signature
from ca_plugins.runner import OciExecutor
from ca_plugins.signature import COSIGN_VERSION, CosignVerifier

DIGEST = "sha256:" + "ab" * 32
REF = f"ghcr.io/ca/demo@{DIGEST}"
MANIFEST = PackagedPluginManifest.model_validate(
    {
        "apiVersion": "code-analyzer/v1",
        "name": "demo",
        "version": "1.0.0",
        "image": f"127.0.0.1:5055/ca/demo:1.0.0@{DIGEST}",
        "capabilities": ["detect"],
        "languages": [],
        "categories": ["quality"],
        "inputs": {"workspace": "readonly"},
        "outputs": {"sarif": "/out/results.sarif", "max_bytes": 1024},
        "resources": {"cpu": "1", "memory": "256Mi", "pids": 64, "timeout": "30s"},
        "network": "none",
    }
)


def script(path: Path, body: str) -> str:
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return str(path)


def fake_cosign(tmp: Path, *, verify_exit: int = 0, version: str = COSIGN_VERSION) -> str:
    return script(
        tmp / "cosign",
        f'''if [ "$1" = version ]; then echo "GitVersion:    {version}"; exit 0; fi
printf '%s\\n' "$@" > "{tmp}/args"
env > "{tmp}/env"
exit {verify_exit}
''',
    )


@pytest.fixture
def key(tmp_path: Path) -> str:
    k = tmp_path / "cosign.pub"
    k.write_text("not a real key")
    return str(k)


def test_valid_signature_command_is_a_list_by_digest(tmp_path: Path, key: str) -> None:
    v = CosignVerifier(public_key=key, cosign=fake_cosign(tmp_path))
    assert v(MANIFEST, REF) is Signature.VERIFIED
    args = (tmp_path / "args").read_text().split("\n")[:-1]
    assert args == ["verify", "--key", key, "--insecure-ignore-tlog=true", REF]


def test_http_registry_flag_only_when_wired(tmp_path: Path, key: str) -> None:
    v = CosignVerifier(public_key=key, cosign=fake_cosign(tmp_path), allow_http_registry=True)
    v(MANIFEST, REF)
    assert "--allow-http-registry" in (tmp_path / "args").read_text().split()


@pytest.mark.parametrize(
    ("registry", "http"),
    [
        ("127.0.0.1:5055", True),
        ("localhost:5055", True),
        ("127.0.0.1.evil.example", False),
        ("ghcr.io", False),
    ],
)
def test_http_is_used_only_for_loopback_references(
    tmp_path: Path, key: str, registry: str, http: bool
) -> None:
    v = CosignVerifier(public_key=key, cosign=fake_cosign(tmp_path))
    assert v(MANIFEST, f"{registry}/ca/demo@{DIGEST}") is Signature.VERIFIED
    assert ("--allow-http-registry" in (tmp_path / "args").read_text().split()) is http


def test_environment_is_an_allowlist(
    tmp_path: Path, key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "segreto")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "segreto")
    CosignVerifier(public_key=key, cosign=fake_cosign(tmp_path))(MANIFEST, REF)
    assert "segreto" not in (tmp_path / "env").read_text()


@pytest.mark.parametrize("code", [1, 2, 127])
def test_any_nonzero_exit_aborts_with_exit_2(tmp_path: Path, key: str, code: int) -> None:
    v = CosignVerifier(public_key=key, cosign=fake_cosign(tmp_path, verify_exit=code))
    with pytest.raises(ScanAborted) as info:
        v(MANIFEST, REF)
    assert info.value.exit_code == 2 and str(code) not in str(info.value)


def test_tag_reference_is_refused_without_running_cosign(tmp_path: Path, key: str) -> None:
    v = CosignVerifier(public_key=key, cosign=fake_cosign(tmp_path))
    for bad in ("127.0.0.1:5055/ca/demo:1.0.0", "-x@" + DIGEST, f"a b@{DIGEST}"):
        with pytest.raises(ScanAborted):
            v(MANIFEST, bad)
    assert not (tmp_path / "args").exists()


def test_cosign_missing_wrong_version_or_hung(tmp_path: Path, key: str) -> None:
    with pytest.raises(ScanAborted, match="cosign"):
        CosignVerifier(public_key=key, cosign=str(tmp_path / "assente"))(MANIFEST, REF)
    with pytest.raises(ScanAborted, match="versione"):
        CosignVerifier(public_key=key, cosign=fake_cosign(tmp_path, version="v9.9.9"))(
            MANIFEST, REF
        )
    hung = script(tmp_path / "hung", "sleep 30\n")
    with pytest.raises(ScanAborted):
        CosignVerifier(public_key=key, cosign=hung, timeout=0.5)(MANIFEST, REF)


def test_no_key_aborts_unless_env_override(tmp_path: Path) -> None:
    cosign = fake_cosign(tmp_path)
    with pytest.raises(ScanAborted, match="chiave"):
        CosignVerifier(public_key=None, cosign=cosign)(MANIFEST, REF)
    with pytest.raises(ScanAborted, match="chiave"):
        CosignVerifier(public_key=str(tmp_path / "manca.pub"), cosign=cosign)(MANIFEST, REF)
    skipped = CosignVerifier(public_key=None, cosign=cosign, allow_unsigned=True)
    assert skipped(MANIFEST, REF) is Signature.SKIPPED
    assert not (tmp_path / "args").exists()


def test_composition_reads_override_only_from_environment() -> None:
    from ca_cli.composition import build_context

    ctx = build_context(environ={})
    assert isinstance(ctx.executor, OciExecutor)
    v = ctx.executor._verifier  # noqa: SLF001
    assert isinstance(v, CosignVerifier)
    with pytest.raises(ScanAborted):  # nessuna chiave: exit 2
        v(MANIFEST, REF)
    skip = build_context(environ={"CA_INSECURE_ALLOW_UNSIGNED": "1"}).executor._verifier  # type: ignore[attr-defined]  # noqa: SLF001
    assert skip(MANIFEST, REF) is Signature.SKIPPED
    other = build_context(environ={"CA_INSECURE_ALLOW_UNSIGNED": "true"}).executor._verifier  # type: ignore[attr-defined]  # noqa: SLF001
    with pytest.raises(ScanAborted):
        other(MANIFEST, REF)


# --- ordine verifica -> pull -> create, con un runtime finto ---------------------------------


def fake_runtime(tmp: Path) -> str:
    return script(
        tmp / "docker",
        f'''echo "$1" >> "{tmp}/calls"
case "$1" in
  info) echo '{json.dumps({"runc": {}})}' ;;
  pull|create|start|kill|rm|ps|volume) exit 0 ;;
  wait) echo 0 ;;
  inspect) echo "0 false" ;;
esac
''',
    )


def request(tmp: Path) -> PluginRunRequest:
    ws = tmp / "ws"
    ws.mkdir(exist_ok=True)
    return PluginRunRequest(manifest=MANIFEST, workspace=str(ws), config=None)


def calls(tmp: Path) -> list[str]:
    f = tmp / "calls"
    return (
        [c for c in f.read_text().split() if c not in {"info", "ps", "volume"}]
        if f.exists()
        else []
    )


def test_verify_then_pull_then_create_and_signature_verified(tmp_path: Path, key: str) -> None:
    v = CosignVerifier(public_key=key, cosign=fake_cosign(tmp_path))
    rt = tmp_path / "rt"
    rt.mkdir()
    (tmp_path / "w").mkdir()
    with OciExecutor(runtime=fake_runtime(rt), work_dir=str(tmp_path / "w"), verifier=v) as ex:
        result = ex.run(request(tmp_path))
    assert result.outcome is RunOutcome.INVALID_OUTPUT  # il finto non scrive /out: non importa qui
    assert result.signature is Signature.VERIFIED
    assert calls(rt)[:2] == ["pull", "create"]


def test_failed_verification_runs_nothing(tmp_path: Path, key: str) -> None:
    v = CosignVerifier(public_key=key, cosign=fake_cosign(tmp_path, verify_exit=1))
    rt = tmp_path / "rt"
    rt.mkdir()
    (tmp_path / "w").mkdir()
    with OciExecutor(runtime=fake_runtime(rt), work_dir=str(tmp_path / "w"), verifier=v) as ex:
        with pytest.raises(ScanAborted):
            ex.run(request(tmp_path))
        with pytest.raises(ScanAborted):
            ex.run_many([request(tmp_path)])
    assert calls(rt) == []


# --- lotti, abort, timeout del client, esito reale (emendamenti ADR-0002/0005) -----------------


def named(name: str) -> PackagedPluginManifest:
    return MANIFEST.model_copy(update={"name": name})


def batch(tmp: Path, *names: str) -> list[PluginRunRequest]:
    ws = tmp / "ws"
    ws.mkdir(exist_ok=True)
    return [PluginRunRequest(manifest=named(n), workspace=str(ws)) for n in names]


def test_denied_signature_in_a_batch_runs_no_create(tmp_path: Path) -> None:
    seen: list[str] = []

    def verifier(m: PackagedPluginManifest, _ref: str) -> Signature:
        seen.append(m.name)
        if m.name == "c":
            raise ScanAborted("firma")
        return Signature.VERIFIED

    rt = tmp_path / "rt"
    rt.mkdir()
    (tmp_path / "w").mkdir()
    with OciExecutor(
        runtime=fake_runtime(rt), work_dir=str(tmp_path / "w"), verifier=verifier, max_parallel=1
    ) as ex:
        with pytest.raises(ScanAborted):
            ex.run_many(batch(tmp_path, "a", "b", "c", "d"))
    assert calls(rt) == []  # nessun pull né create
    assert sorted(seen) == sorted(set(seen))  # una sola verifica per richiesta


def test_later_abort_does_not_wait_for_earlier_and_cancels_unstarted(tmp_path: Path) -> None:
    import threading

    go = threading.Event()
    threading.Timer(0.7, go.set).start()  # rilascia i bloccati: solo dopo l'annullamento
    started: list[str] = []

    def execute(manifest: PackagedPluginManifest, *_a: object, **_k: object) -> object:
        started.append(manifest.name)
        if manifest.name == "r1":
            raise ScanAborted("firma")
        go.wait(10)
        raise AssertionError("non deve completare")

    ex = OciExecutor(runtime=fake_runtime(tmp_path), work_dir=str(tmp_path), max_parallel=2)
    ex._execute = execute  # type: ignore[method-assign,assignment]  # noqa: SLF001
    with pytest.raises((ScanAborted, AssertionError)):
        ex.run_many(batch(tmp_path, *[f"r{i}" for i in range(6)]))
    assert not {"r3", "r4", "r5"} & set(started)  # annullati prima di partire
    ex.close()


def test_create_timeout_is_a_failed_result_and_cleans_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ca_plugins import runner

    monkeypatch.setattr(runner, "_CREATE_TIMEOUT", 0.5)
    rt = tmp_path / "rt"
    rt.mkdir()
    sleepy = script(
        rt / "docker",
        f'''echo "$1" >> "{rt}/calls"
case "$1" in
  info) echo '{json.dumps({"runc": {}})}' ;;
  create) exec sleep 5 ;;
esac
''',
    )
    (tmp_path / "w").mkdir()
    with OciExecutor(runtime=sleepy, work_dir=str(tmp_path / "w")) as ex:
        result = ex.run(batch(tmp_path, "a")[0])
    assert result.outcome is RunOutcome.FAILED and result.exit_code is None
    assert {"kill", "rm"} <= set(calls(rt))


def test_preparation_error_reports_the_real_signature(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(*_a: object, **_k: object) -> list[list[str]]:
        raise OSError("disco pieno")

    monkeypatch.setattr(OciExecutor, "_prepare", staticmethod(broken))
    rt = tmp_path / "rt"
    rt.mkdir()
    (tmp_path / "w").mkdir()
    with OciExecutor(
        runtime=fake_runtime(rt),
        work_dir=str(tmp_path / "w"),
        verifier=lambda _m, _r: Signature.VERIFIED,
    ) as ex:
        result = ex.run(batch(tmp_path, "a")[0])
    assert result.outcome is RunOutcome.FAILED and result.signature is Signature.VERIFIED

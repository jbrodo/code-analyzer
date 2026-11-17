"""B-01: l'applicazione si costruisce, la configurazione viene dall'ambiente, l'export è stabile."""

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ca_api.app import API_VERSION, create_app
from ca_api.config import ConfigError, Settings
from ca_api.openapi_export import FILENAME, main, render

ROOT = Path(__file__).resolve().parents[3]


def test_health_answers_without_any_backend() -> None:
    client = TestClient(create_app(Settings()))
    response = client.get("/v1/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_server_does_not_publish_its_own_documentation() -> None:
    client = TestClient(create_app(Settings()))
    assert all(client.get(p).status_code == 404 for p in ("/docs", "/redoc", "/openapi.json"))


def test_settings_defaults_follow_adr_0016() -> None:
    settings = Settings.from_env({})
    assert (settings.max_part_bytes, settings.max_request_bytes) == (64 * 2**20, 160 * 2**20)


def test_settings_from_environment() -> None:
    env = {"CA_API_MAX_PART_BYTES": "1000", "CA_API_MAX_REQUEST_BYTES": "5000"}
    assert Settings.from_env(env) == Settings(max_part_bytes=1000, max_request_bytes=5000)


@pytest.mark.parametrize(
    "env",
    [
        {"CA_API_MAX_PART_BYTES": "molti"},
        {"CA_API_MAX_PART_BYTES": "0"},
        {"CA_API_MAX_PART_BYTES": "10", "CA_API_MAX_REQUEST_BYTES": "9"},
    ],
    ids=["not-an-int", "zero", "request-below-part"],
)
def test_invalid_settings_fail_at_startup_naming_only_the_variable(env: dict[str, str]) -> None:
    with pytest.raises(ConfigError, match="CA_API_MAX_") as error:
        Settings.from_env(env)
    assert not any(value in str(error.value) for value in env.values() if value.isalpha())


def test_openapi_is_deterministic_and_has_stable_operation_ids() -> None:
    first = render()
    assert first == render()
    document = json.loads(first)
    assert document["info"]["version"] == API_VERSION
    assert document["openapi"].startswith("3.1")
    operations = [op["operationId"] for path in document["paths"].values() for op in path.values()]
    assert operations == ["getHealth"]


def test_export_writes_then_checks(tmp_path: Path) -> None:
    assert main(["--dir", str(tmp_path), "--check"]) == 1  # mancante
    assert main(["--dir", str(tmp_path)]) == 0
    assert main(["--dir", str(tmp_path), "--check"]) == 0
    (tmp_path / FILENAME).write_text("{}\n", encoding="utf-8")
    assert main(["--dir", str(tmp_path), "--check"]) == 1  # divergente


def test_versioned_file_matches_the_application() -> None:
    assert (ROOT / "schemas" / FILENAME).read_text(encoding="utf-8") == render()

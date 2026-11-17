"""I-05: il compose di sviluppo non porta segreti, non espone porte e fissa le immagini."""

import re
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
TEXT = (ROOT / "deploy/compose/server-dev.yaml").read_text()
COMPOSE: dict[str, Any] = yaml.safe_load(TEXT)
SERVICES: dict[str, Any] = COMPOSE["services"]


def test_ports_are_bound_to_loopback_only() -> None:
    for name, service in SERVICES.items():
        for port in service.get("ports", []):
            assert str(port).startswith("127.0.0.1:"), f"{name}: {port}"


def test_database_image_is_pinned_by_digest_and_is_postgres_16() -> None:
    assert re.fullmatch(r"postgres:16@sha256:[0-9a-f]{64}", SERVICES["db"]["image"])


def test_api_image_is_local_and_never_pulled() -> None:
    api = SERVICES["api"]
    assert api["image"] == "ca-server-dev:local" and api["pull_policy"] == "never"


def test_no_secret_in_the_file_and_the_password_is_required_from_the_environment() -> None:
    password = SERVICES["db"]["environment"]["POSTGRES_PASSWORD"]
    assert password.startswith("${CA_DEV_DB_PASSWORD:?")
    assert not re.search(r"(?i)(password|secret|token)\s*[:=]\s*[^\s$?]", re.sub(r"#.*", "", TEXT))


def test_api_runs_hardened() -> None:
    api = SERVICES["api"]
    assert api["read_only"] is True and api["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in api["security_opt"]
    # le tabelle esistono prima che l'API parta: lo garantisce `migrate`
    assert api["depends_on"]["migrate"]["condition"] == "service_completed_successfully"


def test_the_dev_idp_shares_the_api_network_and_every_service_is_hardened() -> None:
    idp = SERVICES["idp"]
    assert idp["network_mode"] == "service:api" and "ports" not in idp  # la porta è sull'API
    assert idp["image"] == "ca-server-dev:local" and idp["pull_policy"] == "never"
    for name in ("idp", "migrate", "api"):
        service = SERVICES[name]
        assert service["read_only"] is True and service["cap_drop"] == ["ALL"], name
        assert "no-new-privileges:true" in service["security_opt"], name


def test_the_dev_auth_file_trusts_only_the_loopback_idp_and_holds_no_secret() -> None:
    import json

    auth = json.loads((ROOT / "deploy/compose/dev-auth.json").read_text())
    for issuer in auth["issuers"]:
        assert issuer["issuer"].startswith("http://127.0.0.1:") and issuer["allow_insecure_dev"]
        assert issuer["jwks_url"].startswith(issuer["issuer"].rsplit("/", 1)[0])
    assert "key" not in json.dumps(auth).lower().replace("jwks", "")


def test_artifacts_live_in_a_named_volume() -> None:
    assert "artifacts:/var/lib/ca/artifacts" in SERVICES["api"]["volumes"]
    assert set(COMPOSE["volumes"]) == {"db-data", "artifacts"}


def test_dev_dockerfile_pins_the_base_and_installs_with_hashes() -> None:
    text = (ROOT / "deploy/docker/server/Dockerfile").read_text()
    assert re.search(r"^FROM python:3\.14-slim-trixie@sha256:[0-9a-f]{64}$", text, re.M)
    assert "--require-hashes" in text and "USER 65532:65532" in text

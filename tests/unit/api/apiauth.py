"""Applicazione con emittenti finti e token pronti, per i test delle route (B-04, B-05)."""

from typing import Any

from fastapi.testclient import TestClient
from idp import (
    GITLAB,
    ISSUER,
    PIPELINE,
    Idp,
    build,
    pipeline_issuer,
    user_issuer,
)

from ca_api.app import create_app
from ca_api.config import Settings

USER_IDP = Idp(ISSUER)
GITHUB_IDP = Idp(PIPELINE)
GITLAB_IDP = Idp(GITLAB, kid="gl1")


def make_client(
    meter_provider: Any = None,
) -> tuple[TestClient, dict[str, str]]:
    """Il client e un'intestazione `Authorization` per ogni tipo di identità."""
    auth, fetcher, _, verifier = build(user_issuer(), pipeline_issuer(), pipeline_issuer("gitlab"))
    for idp in (USER_IDP, GITHUB_IDP, GITLAB_IDP):
        fetcher.publish(idp.jwks_url, idp.jwk())
    app = create_app(Settings(), verifier=verifier, meter_provider=meter_provider)
    client = TestClient(app, raise_server_exceptions=True)

    def bearer(token: str) -> str:
        return f"Bearer {token}"

    def user(*groups: str) -> str:
        return bearer(USER_IDP.sign(groups=list(groups), name="Ada", email="ada@example.org"))

    claims: dict[str, Any] = {
        "repository": "acme/shop",
        "repository_id": "9001",
        "repository_owner_id": "4242",
    }
    tokens = {
        "lettore": user("readers"),
        "triage": user("triagers"),
        "approvatore": user("approvers"),
        "amministratore": user("admins"),
        "tutti": user("readers", "triagers", "approvers", "admins"),
        "nessun ruolo": user(),
        "pipeline": bearer(GITHUB_IDP.sign(GITHUB_IDP.claims(subject="repo", **claims))),
    }
    return client, tokens

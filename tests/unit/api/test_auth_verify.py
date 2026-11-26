"""B-04: verifica dei token OIDC, con i casi obbligatori di ADR-0019. Nessuna rete."""

import base64
import json
from typing import Any

import jwt
import pytest
from idp import (
    AUDIENCE,
    GITLAB,
    ISSUER,
    PIPELINE,
    T0,
    Idp,
    build,
    ec_key,
    pipeline_issuer,
    rsa_key,
    user_issuer,
)

from ca_api.auth.jwks import KeysUnavailable
from ca_api.auth.verify import AuthError
from ca_api.models import Role


@pytest.fixture(scope="module")
def idp() -> Idp:
    return Idp(ISSUER)


@pytest.fixture(scope="module")
def other_key() -> Any:
    return rsa_key()


def setup(idp: Idp, **kv: Any):
    auth, fetcher, clock, verifier = build(user_issuer(), **kv)
    fetcher.publish(idp.jwks_url, idp.jwk())
    return auth, fetcher, clock, verifier


def code(verifier, token: str) -> str:
    with pytest.raises(AuthError) as caught:
        verifier.verify(token)
    return caught.value.code


# --- il caso felice -------------------------------------------------------------------------------


def test_a_valid_user_token_gives_identity_roles_and_the_issuers_tenant(idp: Idp) -> None:
    _, _, _, verifier = setup(idp)
    token = idp.sign(
        groups=["readers", "approvers", "unknown"], name="Ada", email="ada@example.org"
    )
    who = verifier.verify(token)
    assert (who.kind, who.issuer, who.subject, who.tenant) == ("user", ISSUER, "user-1", "acme")
    assert who.roles == frozenset({Role.READER, Role.APPROVER})
    assert (who.name, who.email, who.actor) == ("Ada", "ada@example.org", f"{ISSUER}|user-1")


def test_a_single_string_group_claim_and_no_group_are_both_fine(idp: Idp) -> None:
    _, _, _, verifier = setup(idp)
    assert verifier.verify(idp.sign(groups="admins")).roles == frozenset({Role.ADMIN})
    assert (
        verifier.verify(idp.sign()).roles == frozenset()
    )  # senza ruoli: autenticato ma 403 ovunque


@pytest.mark.parametrize(("algorithm", "key"), [("ES256", ec_key()), ("RS512", rsa_key())])
def test_other_asymmetric_algorithms_are_accepted(algorithm: str, key: Any) -> None:
    other = Idp(ISSUER, key=key, algorithm=algorithm, kid="k2")
    _, _, _, verifier = setup(other)
    assert verifier.verify(other.sign()).subject == "user-1"


# --- emittente ------------------------------------------------------------------------------------


def test_an_unknown_issuer_is_401_and_makes_no_outbound_request(idp: Idp) -> None:
    _, fetcher, _, verifier = setup(idp)
    stranger = Idp("https://evil.example")
    fetcher.publish(stranger.jwks_url, stranger.jwk())
    assert code(verifier, stranger.sign()) == "issuer"
    assert fetcher.calls == []


def test_the_key_address_never_comes_from_the_token(idp: Idp) -> None:
    _, fetcher, _, verifier = setup(idp)
    token = jwt.encode(
        {**idp.claims(), "jku": "https://evil.example/keys"},
        idp.key,
        algorithm="RS256",
        headers={"kid": "k1", "jku": "https://evil.example/keys", "x5u": "https://evil.example/c"},
    )
    assert verifier.verify(token).subject == "user-1"
    assert set(fetcher.calls) == {idp.jwks_url}


def test_a_wrong_audience_is_401(idp: Idp) -> None:
    _, _, _, verifier = setup(idp)
    assert code(verifier, idp.sign(aud="https://another.example")) == "audience"
    assert code(verifier, idp.sign(aud=[AUDIENCE + "x"])) == "audience"


def test_an_audience_list_containing_ours_is_accepted(idp: Idp) -> None:
    _, _, _, verifier = setup(idp)
    assert verifier.verify(idp.sign(aud=["other", AUDIENCE])).subject == "user-1"


# --- firma e algoritmo ------------------------------------------------------------------


def test_a_signature_by_a_key_the_issuer_does_not_publish_is_rejected(
    idp: Idp, other_key: Any
) -> None:
    _, _, _, verifier = setup(idp)
    assert code(verifier, idp.sign(key=other_key)) == "signature"


def test_algorithm_none_is_always_rejected(idp: Idp) -> None:
    _, _, _, verifier = setup(idp)
    header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "kid": "k1"}).encode()).rstrip(
        b"="
    )
    body = base64.urlsafe_b64encode(json.dumps(idp.claims()).encode()).rstrip(b"=")
    assert code(verifier, f"{header.decode()}.{body.decode()}.") == "algorithm"


def forged_hmac(claims: dict[str, Any], secret: bytes, alg: str, kid: str = "k1") -> str:
    """Un token firmato con HMAC a mano (la libreria rifiuta di usare una chiave pubblica così)."""
    import hashlib
    import hmac

    def part(value: dict[str, Any]) -> str:
        raw = json.dumps(value, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    signing = f"{part({'alg': alg, 'typ': 'JWT', 'kid': kid})}.{part(claims)}"
    digest = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}[alg]
    signature = hmac.new(secret, signing.encode(), digest).digest()
    return signing + "." + base64.urlsafe_b64encode(signature).rstrip(b"=").decode()


@pytest.mark.parametrize("alg", ["HS256", "HS384", "HS512"])
def test_symmetric_algorithms_are_rejected_even_with_the_public_key_as_secret(
    idp: Idp, alg: str
) -> None:
    """Attacco di confusione dell'algoritmo: HS256 con la chiave pubblica come segreto."""
    _, _, _, verifier = setup(idp)
    public = json.dumps(idp.jwk()).encode()
    assert code(verifier, forged_hmac(idp.claims(), public, alg)) == "algorithm"


def test_a_symmetric_jwks_entry_is_ignored(idp: Idp) -> None:
    auth, fetcher, _, verifier = build(user_issuer())
    secret = base64.urlsafe_b64encode(b"shared-secret-shared-secret-shared").rstrip(b"=").decode()
    fetcher.publish(idp.jwks_url, {"kty": "oct", "k": secret, "kid": "k1"})
    token = jwt.encode(
        idp.claims(),
        b"shared-secret-shared-secret-shared",
        algorithm="HS256",
        headers={"kid": "k1"},
    )
    assert code(verifier, token) == "algorithm"
    assert code(verifier, idp.sign()) == "keys"  # il kid non ha una chiave asimmetrica


@pytest.mark.parametrize(
    "token", ["", "abc", "a.b", "a.b.c.d", "x" * 20_000, "é.é.é", "..", "a..c"]
)
def test_malformed_tokens_are_401_without_echoing_anything(idp: Idp, token: str) -> None:
    _, _, _, verifier = setup(idp)
    with pytest.raises(AuthError) as caught:
        verifier.verify(token)
    assert (
        caught.value.code in {"malformed", "algorithm"}
        and token not in str(caught.value)
        or token == ""
    )


def test_a_token_without_kid_is_refused(idp: Idp) -> None:
    _, _, _, verifier = setup(idp)
    assert code(verifier, idp.sign(kid=None)) == "kid"


# --- tempo ---------------------------------------------------------------------------------------


def test_an_expired_token_is_401_but_the_clock_skew_is_tolerated(idp: Idp) -> None:
    _, _, clock, verifier = setup(idp)
    now = int(T0.timestamp())
    assert verifier.verify(idp.sign(idp.claims(exp=now - 30, iat=now - 600))).subject
    assert code(verifier, idp.sign(idp.claims(exp=now - 61, iat=now - 600))) == "expired"
    clock.advance(3600)
    assert code(verifier, idp.sign()) == "expired"


def test_not_before_in_the_future_is_401_beyond_the_skew(idp: Idp) -> None:
    _, _, _, verifier = setup(idp)
    now = int(T0.timestamp())
    assert verifier.verify(idp.sign(idp.claims(nbf=now + 30))).subject
    assert code(verifier, idp.sign(idp.claims(nbf=now + 120))) == "not-yet-valid"


def test_a_token_issued_in_the_future_is_401(idp: Idp) -> None:
    _, _, _, verifier = setup(idp)
    now = int(T0.timestamp())
    assert (
        code(verifier, idp.sign(idp.claims(iat=now + 3600, exp=now + 4200)))
        == "issued-in-the-future"
    )


def test_a_lifetime_beyond_the_maximum_is_refused(idp: Idp) -> None:
    _, _, _, verifier = setup(idp)
    now = int(T0.timestamp())
    assert code(verifier, idp.sign(idp.claims(iat=now, exp=now + 7200))) == "lifetime"
    assert verifier.verify(idp.sign(idp.claims(iat=now, exp=now + 3600))).subject
    _, _, _, longer = setup(idp, max_token_lifetime_seconds=7200)
    assert longer.verify(idp.sign(idp.claims(iat=now, exp=now + 7200))).subject


@pytest.mark.parametrize("missing", ["exp", "iat", "sub", "aud", "iss"])
def test_the_required_claims_must_be_present(idp: Idp, missing: str) -> None:
    _, _, _, verifier = setup(idp)
    claims = idp.claims()
    del claims[missing]
    assert code(verifier, idp.sign(claims)) in {"signature", "issuer", "audience"}


@pytest.mark.parametrize("bad", [True, "soon", None])
def test_a_non_numeric_exp_is_refused(idp: Idp, bad: Any) -> None:
    _, _, _, verifier = setup(idp)
    assert code(verifier, idp.sign(idp.claims(exp=bad))) in {"signature", "time"}


# --- chiavi ---------------------------------------------------------------------------------------


def test_keys_are_cached_until_the_ttl_then_fetched_again(idp: Idp) -> None:
    _, fetcher, clock, verifier = setup(idp)
    verifier.verify(idp.sign())
    verifier.verify(idp.sign())
    assert len(fetcher.calls) == 1
    clock.advance(301)
    now = int(clock.now().timestamp())
    verifier.verify(idp.sign(idp.claims(iat=now, exp=now + 600)))
    assert len(fetcher.calls) == 2


def test_an_unknown_kid_causes_one_refresh_and_then_a_rate_limit(idp: Idp) -> None:
    _, fetcher, clock, verifier = setup(idp)
    verifier.verify(idp.sign())  # prima richiesta
    assert len(fetcher.calls) == 1
    clock.advance(31)
    now = int(clock.now().timestamp())
    for _ in range(20):
        assert code(verifier, idp.sign(idp.claims(iat=now, exp=now + 600), kid="ghost")) == "keys"
    assert len(fetcher.calls) == 2  # un solo aggiornamento, poi il limite di frequenza


def test_a_key_rotation_is_picked_up_after_one_refresh(idp: Idp) -> None:
    _, fetcher, clock, verifier = setup(idp)
    verifier.verify(idp.sign())
    new = Idp(ISSUER, kid="k2", key=rsa_key())
    fetcher.publish(idp.jwks_url, idp.jwk(), new.jwk())
    clock.advance(31)
    now = int(clock.now().timestamp())
    assert verifier.verify(new.sign(new.claims(iat=now, exp=now + 600))).subject == "user-1"


def test_an_unreachable_or_broken_jwks_is_401_not_a_crash(idp: Idp) -> None:
    _, fetcher, _, verifier = build(user_issuer())
    assert code(verifier, idp.sign()) == "keys"  # nessun documento
    fetcher.documents[idp.jwks_url] = KeysUnavailable("network")
    assert code(verifier, idp.sign()) == "keys"
    for broken in (b"{", b"[]", b'{"keys": "x"}', b'{"keys": [1, null]}'):
        fetcher.documents[idp.jwks_url] = broken
        assert code(verifier, idp.sign()) == "keys"


def test_a_jwks_with_too_many_keys_is_refused(idp: Idp) -> None:
    _, fetcher, _, verifier = build(user_issuer())
    fetcher.documents[idp.jwks_url] = json.dumps({"keys": [idp.jwk()] * 51}).encode()
    assert code(verifier, idp.sign()) == "keys"


# --- pipeline -------------------------------------------------------------------------------------


def github_claims(idp: Idp, **kv: Any) -> dict[str, Any]:
    claims = {
        "repository": "acme/shop",
        "repository_id": "9001",
        "repository_owner_id": "4242",
        "ref": "refs/heads/main",
        "sha": "a" * 40,
    }
    return idp.claims(subject="repo:acme/shop:ref:refs/heads/main", **{**claims, **kv})


def test_a_github_pipeline_token_gives_the_numeric_repository_identity() -> None:
    gh = Idp(PIPELINE)
    _, fetcher, _, verifier = build(pipeline_issuer())
    fetcher.publish(gh.jwks_url, gh.jwk())
    who = verifier.verify(gh.sign(github_claims(gh)))
    repo = who.repository
    assert who.kind == "pipeline" and who.tenant == "acme" and who.roles == frozenset()
    assert repo is not None
    assert (repo.provider, repo.external_id, repo.owner_id) == ("github", "9001", "4242")
    assert (repo.name, repo.ref, repo.sha) == ("acme/shop", "refs/heads/main", "a" * 40)


def test_a_gitlab_pipeline_token_uses_the_gitlab_claim_names() -> None:
    gl = Idp(GITLAB)
    _, fetcher, _, verifier = build(pipeline_issuer("gitlab"))
    fetcher.publish(gl.jwks_url, gl.jwk())
    claims = gl.claims(project_id="77", namespace_id=4242, project_path="acme/shop", ref="main")
    repo = verifier.verify(gl.sign(claims)).repository
    assert repo is not None and (repo.provider, repo.external_id, repo.name) == (
        "gitlab",
        "77",
        "acme/shop",
    )


def test_the_repository_is_identified_by_id_not_by_name() -> None:
    gh = Idp(PIPELINE)
    _, fetcher, _, verifier = build(pipeline_issuer())
    fetcher.publish(gh.jwks_url, gh.jwk())
    renamed = verifier.verify(gh.sign(github_claims(gh, repository="acme/renamed"))).repository
    original = verifier.verify(gh.sign(github_claims(gh))).repository
    assert renamed is not None and original is not None
    assert renamed.external_id == original.external_id and renamed.name != original.name


def test_an_owner_outside_the_map_is_403_not_401() -> None:
    gh = Idp(PIPELINE)
    _, fetcher, _, verifier = build(pipeline_issuer())
    fetcher.publish(gh.jwks_url, gh.jwk())
    with pytest.raises(AuthError) as caught:
        verifier.verify(gh.sign(github_claims(gh, repository_owner_id="999")))
    assert caught.value.forbidden and caught.value.code == "owner"


@pytest.mark.parametrize("missing", ["repository_id", "repository_owner_id"])
def test_a_pipeline_token_without_its_identity_claims_is_401(missing: str) -> None:
    gh = Idp(PIPELINE)
    _, fetcher, _, verifier = build(pipeline_issuer())
    fetcher.publish(gh.jwks_url, gh.jwk())
    claims = github_claims(gh)
    del claims[missing]
    assert code(verifier, gh.sign(claims)) == "claims"


@pytest.mark.parametrize("bad", [True, "12ab", "", 3.5, None, [1]])
def test_pipeline_ids_must_be_digits(bad: Any) -> None:
    gh = Idp(PIPELINE)
    _, fetcher, _, verifier = build(pipeline_issuer())
    fetcher.publish(gh.jwks_url, gh.jwk())
    assert code(verifier, gh.sign(github_claims(gh, repository_id=bad))) == "claims"


def test_a_user_issuer_token_never_becomes_a_pipeline_identity_and_vice_versa(idp: Idp) -> None:
    gh = Idp(PIPELINE)
    auth, fetcher, _, verifier = build(user_issuer(), pipeline_issuer())
    fetcher.publish(idp.jwks_url, idp.jwk())
    fetcher.publish(gh.jwks_url, gh.jwk())
    assert verifier.verify(idp.sign(repository_id="1", repository_owner_id="4242")).kind == "user"
    assert verifier.verify(gh.sign(github_claims(gh))).kind == "pipeline"
    assert code(verifier, Idp(ISSUER, key=rsa_key()).sign()) == "signature"  # chiave non pubblicata

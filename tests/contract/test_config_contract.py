"""`code-analyzer-config`: contratto del file `.code-analyzer.yml` letto come JSON.

Le chiavi di esecuzione dei plugin sono vietate (ADR-0014): il repository analizzato non
decide immagine, digest, firma, isolamento, rete, montaggi, comando né origine dei feed.
"""

import pytest
from conftest import Json, errors_of, make_validator, mutated

VALIDATOR = make_validator("code-analyzer-config")
FP = "sha256:" + "b" * 64
EXC = {"fingerprint": FP, "reason": "r", "expires": "2027-01-31", "approved_by": "sec"}

MINIMAL: Json = {"version": 1}
FULL: Json = {
    "version": 1,
    "languages": ["python"],
    "paths": {"exclude": ["vendor/**"]},
    "gate": {"mode": "new-findings-only", "block_on": ["critico"], "warn_on": ["alto", "medio"]},
    "licenses": {
        "forbidden": ["GPL-3.0"],
        "require_approval": ["MPL-2.0"],
        "distributed_product": True,
    },
    "plugins": {"disable": ["scancode"], "semgrep": {"rules": ["p/ci"]}},
    "exceptions": [EXC],
    "service": {"tier": 1, "internet_facing": True, "catalog_id": "svc"},
    "scoring": {"variant": "B"},
    "agents": {"enabled": False, "llm_provider": "x", "max_phase": 8},
}

VALID = {
    "minimal": MINIMAL,
    "full": FULL,
    "empty-sections": {"version": 1, "paths": {}, "gate": {}, "plugins": {}, "licenses": {}},
    "null-sections": {"version": 1, "service": None, "scoring": None, "agents": None},
    "agents-max-phase-lower": {"version": 1, "agents": {"max_phase": 1}},
    "plugins-semgrep-null": {"version": 1, "plugins": {"semgrep": None}},
}

# Chiavi vietate (ADR-0014), nelle posizioni in cui un autore le proverebbe a mettere.
FORBIDDEN_KEYS = (
    "image",
    "digest",
    "signature",
    "isolation",
    "network",
    "mounts",
    "volumes",
    "command",
    "sync_command",
    "feeds",
    "feed_origin",
    "origin",
    "entrypoint",
    "args",
)
FORBIDDEN = {}
for key in FORBIDDEN_KEYS:
    FORBIDDEN[f"top-level-{key}"] = {"version": 1, key: "x"}
    FORBIDDEN[f"plugins-{key}"] = {"version": 1, "plugins": {key: "x"}}
    FORBIDDEN[f"plugins-semgrep-{key}"] = {"version": 1, "plugins": {"semgrep": {key: "x"}}}
FORBIDDEN["plugins-per-plugin-image"] = {"version": 1, "plugins": {"trivy": {"image": "x:1"}}}
FORBIDDEN["plugins-enable"] = {"version": 1, "plugins": {"enable": ["x"]}}

INVALID = {
    "missing-version": {},
    "version-2": {"version": 2},
    "version-string": {"version": "1"},
    "version-float": {"version": 1.5},
    "unknown-top-level": {"version": 1, "foo": 1},
    "gate-mode-unknown": {"version": 1, "gate": {"mode": "none"}},
    "gate-level-unknown": {"version": 1, "gate": {"block_on": ["urgent"]}},
    "gate-unknown-key": {"version": 1, "gate": {"fail_on": ["alto"]}},
    "scoring-variant-C": {"version": 1, "scoring": {"variant": "C"}},
    "scoring-variant-lowercase": {"version": 1, "scoring": {"variant": "a"}},
    "scoring-unknown-key": {"version": 1, "scoring": {"weights": {}}},
    "agents-max-phase-0": {"version": 1, "agents": {"max_phase": 0}},
    "agents-max-phase-9": {"version": 1, "agents": {"max_phase": 9}},
    "service-tier-0": {"version": 1, "service": {"tier": 0}},
    "service-unknown-key": {"version": 1, "service": {"owner": "x"}},
    "paths-exclude-not-array": {"version": 1, "paths": {"exclude": "a"}},
    "paths-unknown-key": {"version": 1, "paths": {"include": ["a"]}},
    "licenses-unknown-key": {"version": 1, "licenses": {"allowed": ["MIT"]}},
    "exception-missing-reason": {
        "version": 1,
        "exceptions": [{k: v for k, v in EXC.items() if k != "reason"}],
    },
    "exception-empty-reason": {
        "version": 1,
        "exceptions": [mutated(EXC, lambda e: e.update(reason=""))],
    },
    "exception-empty-approver": {
        "version": 1,
        "exceptions": [mutated(EXC, lambda e: e.update(approved_by=""))],
    },
    "exception-bad-fingerprint": {
        "version": 1,
        "exceptions": [mutated(EXC, lambda e: e.update(fingerprint="abc"))],
    },
    "exception-bad-date": {
        "version": 1,
        "exceptions": [mutated(EXC, lambda e: e.update(expires="31/01/2027"))],
    },
    "exception-impossible-date": {
        "version": 1,
        "exceptions": [mutated(EXC, lambda e: e.update(expires="2027-02-30"))],
    },
    "exception-unknown-key": {"version": 1, "exceptions": [mutated(EXC, lambda e: e.update(x=1))]},
    "languages-not-strings": {"version": 1, "languages": [1]},
}


@pytest.mark.parametrize("instance", VALID.values(), ids=VALID.keys())
def test_valid_config_is_accepted(instance: Json) -> None:
    assert errors_of(VALIDATOR, instance) == []


@pytest.mark.parametrize("instance", INVALID.values(), ids=INVALID.keys())
def test_invalid_config_is_rejected(instance: Json) -> None:
    assert errors_of(VALIDATOR, instance) != []


@pytest.mark.parametrize("instance", FORBIDDEN.values(), ids=FORBIDDEN.keys())
def test_forbidden_execution_key_is_rejected(instance: Json) -> None:
    assert errors_of(VALIDATOR, instance) != []

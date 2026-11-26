"""`scoring-benchmark`: distribuzione di benchmark della Variante B (ADR-0023, K-06)."""

import pytest
from conftest import Json, case_params, errors_of, make_validator, mutated

VALIDATOR = make_validator("scoring-benchmark")
QUANTILES = [float(i // 10) for i in range(101)]

VALID_FILE: Json = {
    "version": 1,
    "created_at": "2026-11-26T10:00:00Z",
    "levels": [float(i) for i in range(101)],
    "corpus": [
        {"url": "https://github.com/pallets/flask", "commit": "a" * 40, "tag": "3.1.2"},
        {"url": "https://github.com/expressjs/express", "commit": "b" * 40, "tag": None},
    ],
    "engines": {"ruff": "0.17.5", "eslint": "10.0.0", "ca-graph": "1.0.0"},
    "code_metrics": [
        {
            "engine": "ruff",
            "rule_id": "C901",
            "repositories": 2,
            "observations": 1500,
            "quantiles": QUANTILES,
        }
    ],
    "smell_sizes": [
        {
            "rule_id": "ca.arch.cyclic-dependency",
            "scope": "module",
            "repositories": 1,
            "observations": 12,
            "quantiles": QUANTILES,
        }
    ],
}


def _metric(**changes: object):
    return lambda i: i["code_metrics"][0].update(changes)


VALID = {
    "full": VALID_FILE,
    "no-tag": mutated(VALID_FILE, lambda i: i["corpus"][0].pop("tag")),
    "empty-distributions": mutated(VALID_FILE, lambda i: i.update(code_metrics=[], smell_sizes=[])),
    "integer-quantiles": mutated(VALID_FILE, _metric(quantiles=list(range(101)))),
    "dense-tail": mutated(
        VALID_FILE,
        lambda i: i.update(levels=[*range(90), *(90 + t / 10 for t in range(101))]),
    ),
    "eslint-rule": mutated(VALID_FILE, _metric(engine="eslint", rule_id="max-lines-per-function")),
    "package-scope": mutated(VALID_FILE, lambda i: i["smell_sizes"][0].update(scope="package")),
}

INVALID = {
    "empty": {},
    "no-corpus": mutated(VALID_FILE, lambda i: i.update(corpus=[])),
    "not-github": mutated(VALID_FILE, lambda i: i["corpus"][0].update(url="https://x.org/a/b")),
    "short-commit": mutated(VALID_FILE, lambda i: i["corpus"][0].update(commit="abc")),
    "unknown-key": mutated(VALID_FILE, lambda i: i.update(paths=["src/a.py"])),
    "metric-extra-key": mutated(VALID_FILE, _metric(functions=["handler"])),
    "unknown-engine": mutated(VALID_FILE, _metric(engine="pylint")),
    "one-quantile": mutated(VALID_FILE, _metric(quantiles=[1.0])),
    "too-many-quantiles": mutated(VALID_FILE, _metric(quantiles=[1.0] * 1002)),
    "no-levels": mutated(VALID_FILE, lambda i: i.pop("levels")),
    "level-over-100": mutated(VALID_FILE, lambda i: i["levels"].__setitem__(-1, 100.5)),
    "level-string": mutated(VALID_FILE, lambda i: i["levels"].__setitem__(0, "0")),
    "negative-quantile": mutated(VALID_FILE, _metric(quantiles=[-1.0, *QUANTILES[1:]])),
    "quantile-string": mutated(VALID_FILE, _metric(quantiles=["1", *QUANTILES[1:]])),
    "zero-observations": mutated(VALID_FILE, _metric(observations=0)),
    "bad-scope": mutated(VALID_FILE, lambda i: i["smell_sizes"][0].update(scope="file")),
    "version-0": mutated(VALID_FILE, lambda i: i.update(version=0)),
    "no-engines": mutated(VALID_FILE, lambda i: i.update(engines={})),
    "rule-with-space": mutated(VALID_FILE, _metric(rule_id="C 901")),
}


@pytest.mark.parametrize("instance", case_params(VALID, "valid:"))
def test_valid_instances_pass(instance: Json) -> None:
    assert errors_of(VALIDATOR, instance) == []


@pytest.mark.parametrize("instance", case_params(INVALID, "invalid:"))
def test_invalid_instances_are_rejected(instance: Json) -> None:
    assert errors_of(VALIDATOR, instance) != []

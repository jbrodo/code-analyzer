"""`golden-sample` e `golden-labels`: il golden set del triage (G3-02), solo riferimenti."""

import pytest
from conftest import Json, errors_of, make_validator, mutated

VALIDATORS = {name: make_validator(name) for name in ("golden-sample", "golden-labels")}
DIGEST = "sha256:" + "a" * 64
REPOSITORY = "https://github.com/pallets/flask"

SAMPLE: Json = {
    "version": 1,
    "set": "pilota",
    "language": "python",
    "sampling": {
        "seed": "pilota-1",
        "cap_per_repository_and_rule": 20,
        "excluded_rules": ["B101"],
        "pool_size": 700,
    },
    "items": [
        {
            "repository": REPOSITORY,
            "commit": "b" * 40,
            "tool": "bandit",
            "rule_id": "B608",
            "path": "src/app.py",
            "start_line": 10,
            "end_line": 12,
            "fingerprint": DIGEST,
        }
    ],
}

LABELS: Json = {
    "version": 1,
    "set": "pilota",
    "sample_sha256": DIGEST,
    "annotator": "annotatore-1",
    "round": 1,
    "delivered_at": "2026-11-28T10:00:00Z",
    "labels": [{"repository": REPOSITORY, "fingerprint": DIGEST, "label": "vero", "seconds": 40}],
}


def _item(**changes: object):
    return lambda i: i["items"][0].update(changes)


def _label(**changes: object):
    return lambda i: i["labels"][0].update(changes)


VALID = {
    "golden-sample": {
        "full": SAMPLE,
        "second-pilot": mutated(SAMPLE, lambda i: i.update(set="pilota-2")),
        "semgrep": mutated(SAMPLE, _item(tool="semgrep", rule_id="ca-py-weak-hash")),
        "nothing-excluded": mutated(SAMPLE, lambda i: i["sampling"].update(excluded_rules=[])),
    },
    "golden-labels": {
        "full": LABELS,
        "false-positive": mutated(LABELS, _label(label="falso-positivo")),
        "unsure": mutated(LABELS, _label(label="non-so", seconds=0)),
        "second-round": mutated(LABELS, lambda i: i.update(round=2)),
    },
}

INVALID = {
    "golden-sample": {
        "no-items": mutated(SAMPLE, lambda i: i.update(items=[])),
        "code-copy": mutated(SAMPLE, _item(snippet="x = 1")),
        "message-copy": mutated(SAMPLE, _item(message="testo del tool")),
        "level-shown": mutated(SAMPLE, _item(level="critico")),
        "private-url": mutated(SAMPLE, _item(repository="file:///home/a/repo")),
        "short-commit": mutated(SAMPLE, _item(commit="abc")),
        "absolute-path": mutated(SAMPLE, _item(path="/etc/passwd")),
        "line-zero": mutated(SAMPLE, _item(start_line=0)),
        "bad-set": mutated(SAMPLE, lambda i: i.update(set="prova")),
        "other-language": mutated(SAMPLE, lambda i: i.update(language="javascript")),
    },
    "golden-labels": {
        "no-labels": mutated(LABELS, lambda i: i.update(labels=[])),
        "unknown-label": mutated(LABELS, _label(label="forse")),
        "note-copy": mutated(LABELS, _label(note="la riga fa x = 1")),
        "model-annotator": mutated(LABELS, lambda i: i.update(annotator="laya")),
        "personal-name": mutated(LABELS, lambda i: i.update(annotator="Mario Rossi")),
        "negative-seconds": mutated(LABELS, _label(seconds=-1)),
        "no-sample-digest": mutated(LABELS, lambda i: i.pop("sample_sha256")),
        "round-zero": mutated(LABELS, lambda i: i.update(round=0)),
    },
}


def cases(table: dict[str, dict[str, Json]]) -> list:
    return [
        pytest.param(name, instance, id=f"{name}:{case}")
        for name, group in table.items()
        for case, instance in group.items()
    ]


@pytest.mark.parametrize("name,instance", cases(VALID))
def test_valid_instances_pass(name: str, instance: Json) -> None:
    assert errors_of(VALIDATORS[name], instance) == []


@pytest.mark.parametrize("name,instance", cases(INVALID))
def test_invalid_instances_fail(name: str, instance: Json) -> None:
    assert errors_of(VALIDATORS[name], instance)

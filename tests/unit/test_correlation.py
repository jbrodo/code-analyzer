"""K-21: gruppi di correlazione tra strumenti, con gli attesi di F-02 (`iac-app`)."""

from pathlib import Path
from typing import Any

import pytest
import yaml
from builders import finding

from ca_core import correlation as corr
from ca_core.correlation import (
    TABLE,
    TABLE_VERSION,
    assign_correlation,
    canonical_key,
    group_id,
    group_members,
    representatives,
)
from ca_core.fakes import FixedClock, InMemorySourceReader
from ca_core.models import CodeAnalyzerConfig
from ca_core.models.finding import Category, Finding, Level
from ca_core.pipeline.normalize import NormalizeRequest, normalize
from ca_core.schema_validation import SchemaStore

ROOT = Path(__file__).resolve().parents[2]
EXPECTED = yaml.safe_load(
    (ROOT / "tests/fixtures/repos/iac-app/expected-findings.yaml").read_text()
)


def one(n: str, tool: str, rule: str, path: str | None = "Dockerfile", **kw: Any) -> Finding:
    base = finding(n, category=Category.IAC, tool=tool, path=path, **kw)
    return base.model_copy(update={"rule_id": rule})


def from_expected() -> list[tuple[dict[str, Any], Finding]]:
    out = []
    for i, entry in enumerate(EXPECTED["expected"]):
        out.append((entry, one(f"e{i}", entry["tools"][0], entry["rule_id"], entry["path"])))
    return out


# --- la tabella --------------------------------------------------------------------------------


def test_the_table_covers_exactly_the_correlated_problems_of_the_f02_fixture() -> None:
    labelled = {e["correlation"] for e in EXPECTED["expected"] if "correlation" in e}
    assert {k for k in TABLE.values()} == labelled


def test_every_expected_rule_maps_to_the_key_the_fixture_declares() -> None:
    for entry, _ in from_expected():
        key = canonical_key(entry["tools"][0], entry["rule_id"])
        assert key == entry.get("correlation"), entry["rule_id"]


def test_a_rule_cannot_belong_to_two_problems() -> None:
    with pytest.raises(ValueError, match="due problemi"):
        corr._invert({"a": {"trivy": ("DS-1",)}, "b": {"trivy": ("DS-1",)}})


def test_unknown_rules_have_no_key() -> None:
    assert canonical_key("trivy", "DS-9999") is None and canonical_key("semgrep", "DS-0001") is None


# --- gruppi sulle fixture -----------------------------------------------------------------------


def test_f02_findings_seen_by_several_tools_share_a_group_and_the_others_have_none() -> None:
    pairs = from_expected()
    assigned = assign_correlation(f for _, f in pairs)
    by_label: dict[tuple[str, str], set[str | None]] = {}
    for (entry, _), result in zip(pairs, assigned, strict=True):
        label = entry.get("correlation")
        if label is None:
            assert result.correlation is None, entry["rule_id"]
            continue
        by_label.setdefault((label, entry["path"]), set()).add(result.correlation)
    assert all(len(groups) == 1 and None not in groups for groups in by_label.values())
    assert len({next(iter(g)) for g in by_label.values()}) == len(by_label)  # gruppi distinti
    assert len(by_label) == 11


def test_a_three_tool_problem_has_one_group_of_three() -> None:
    found = assign_correlation(
        [
            one("a", "trivy", "DS-0001"),
            one("b", "checkov", "CKV_DOCKER_7"),
            one("c", "hadolint", "DL3007"),
        ]
    )
    assert len({f.correlation for f in found}) == 1 and found[0].correlation is not None
    assert len(group_members(found)[found[0].correlation]) == 3


def test_grouping_never_changes_fingerprint_level_score_or_anything_else() -> None:
    items = [one("a", "trivy", "DS-0001", level=Level.MEDIUM), one("b", "checkov", "CKV_DOCKER_7")]
    out = assign_correlation(items)
    for before, after in zip(items, out, strict=True):
        assert before.model_dump(exclude={"correlation"}) == after.model_dump(
            exclude={"correlation"}
        )
        assert before.fingerprint == after.fingerprint and before.correlation is None


def test_input_order_and_length_are_preserved() -> None:
    items = [
        one(c, t, r)
        for c, t, r in (
            ("a", "checkov", "CKV_DOCKER_7"),
            ("z", "hadolint", "DL3020"),
            ("m", "trivy", "DS-0001"),
        )
    ]
    assert [f.fingerprint for f in assign_correlation(items)] == [f.fingerprint for f in items]


# --- quando NON c'è gruppo -----------------------------------------------------------------------


@pytest.mark.parametrize(
    "items",
    [
        [one("a", "trivy", "DS-0001")],  # un solo strumento
        [
            one("a", "trivy", "DS-0001"),
            one("b", "trivy", "DS-0001", "Dockerfile"),
        ],  # stesso strumento
        [
            one("a", "trivy", "DS-0001", "a/Dockerfile"),
            one("b", "checkov", "CKV_DOCKER_7", "b/Dockerfile"),
        ],
        [one("a", "trivy", "DS-0001"), one("b", "checkov", "CKV_DOCKER_4")],  # problemi diversi
        [
            one("a", "trivy", "DS-0001", None),
            one("b", "checkov", "CKV_DOCKER_7", None),
        ],  # senza file
        [one("a", "trivy", "DS-9999"), one("b", "checkov", "CKV_DOCKER_7")],  # regola senza voce
    ],
    ids=["one-tool", "same-tool", "other-file", "other-problem", "no-path", "unknown-rule"],
)
def test_no_group(items: list[Finding]) -> None:
    assert all(f.correlation is None for f in assign_correlation(items))


def test_a_different_category_is_not_the_same_problem() -> None:
    sast = finding("s", category=Category.SAST, tool="checkov", path="Dockerfile").model_copy(
        update={"rule_id": "CKV_DOCKER_7"}
    )
    assert assign_correlation([one("a", "trivy", "DS-0001"), sast])[0].correlation is None


def test_two_findings_of_the_same_tool_join_a_group_confirmed_by_another() -> None:
    items = [
        one("a", "trivy", "KSV-0017", "k.yaml"),
        one("b", "trivy", "KSV-0017", "k.yaml"),
        one("c", "checkov", "CKV_K8S_16", "k.yaml"),
    ]
    assert len({f.correlation for f in assign_correlation(items)}) == 1


def test_group_ids_are_stable_prefixed_and_depend_on_category_path_and_key() -> None:
    base = group_id("iac", "Dockerfile", "dockerfile.sudo")
    assert base == group_id("iac", "Dockerfile", "dockerfile.sudo") and base.startswith("cg1:")
    assert len(base) == 4 + 16
    assert (
        len(
            {
                base,
                group_id("sast", "Dockerfile", "dockerfile.sudo"),
                group_id("iac", "other/Dockerfile", "dockerfile.sudo"),
                group_id("iac", "Dockerfile", "dockerfile.latest-tag"),
            }
        )
        == 4
    )


# --- un solo rappresentante ---------------------------------------------------------


def test_representatives_keep_one_per_group_the_most_severe_and_all_the_ungrouped() -> None:
    low = one("a", "hadolint", "DL3007", level=Level.LOW)
    high = one("b", "trivy", "DS-0001", level=Level.HIGH)
    mid = one("c", "checkov", "CKV_DOCKER_7", level=Level.MEDIUM)
    alone = one("d", "hadolint", "DL3008", level=Level.LOW)
    grouped = assign_correlation([low, high, mid, alone])
    assert representatives(grouped) == [grouped[1], grouped[3]]


def test_representatives_of_nothing_and_of_an_ungrouped_list() -> None:
    assert representatives([]) == []
    plain = [one("a", "trivy", "DS-0001"), one("b", "checkov", "CKV_DOCKER_4")]
    assert representatives(assign_correlation(plain)) == plain


def test_ties_are_broken_by_fingerprint_so_the_choice_is_deterministic() -> None:
    items = assign_correlation(
        [
            one("a", "trivy", "DS-0001", level=Level.HIGH),
            one("b", "checkov", "CKV_DOCKER_7", level=Level.HIGH),
        ]
    )
    chosen = representatives(items)
    assert chosen == representatives(list(reversed(items))) and len(chosen) == 1
    assert chosen[0].fingerprint == min(f.fingerprint for f in items)


# --- con normalize -------------------------------------------------------------------


@pytest.fixture(scope="module")
def store() -> SchemaStore:
    return SchemaStore(ROOT / "schemas" / "vendor")


def test_normalize_assigns_groups_and_keeps_every_fingerprint(store: SchemaStore) -> None:
    items = [
        one("a", "trivy", "DS-0001"),
        one("b", "checkov", "CKV_DOCKER_7"),
        one("c", "hadolint", "DL3008"),
    ]
    result = normalize(
        NormalizeRequest(
            repository="repo", workspace="/ws", executions=[],
            config=CodeAnalyzerConfig.model_validate({"version": 1}), extra_findings=items,
        ),
        InMemorySourceReader(),
        store,
        FixedClock(),
    )  # fmt: skip
    assert sorted(f.fingerprint for f in result.findings) == sorted(f.fingerprint for f in items)
    grouped = [f for f in result.findings if f.correlation]
    assert {f.tool for f in grouped} == {"trivy", "checkov"}
    assert next(f for f in result.findings if f.tool == "hadolint").correlation is None


def test_the_table_version_is_a_short_number_the_report_accepts() -> None:
    assert TABLE_VERSION.isdigit()

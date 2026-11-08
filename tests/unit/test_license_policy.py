"""K-12: motore della policy licenze. Policy di test, separata da quella del prodotto."""

import pytest
from builders import NOW, finding

from ca_core.fakes import FixedClock
from ca_core.models.config import Licenses
from ca_core.models.finding import Category, Level, LevelSource
from ca_core.normalize import DeclaredLicense
from ca_core.policy.licenses import (
    LicenseLevelTable,
    SpdxSyntaxError,
    Verdict,
    evaluate_expression,
    evaluate_licenses,
    parse_expression,
)

POLICY = Licenses(
    forbidden=["AGPL-3.0-only", "SSPL-1.0"],
    require_approval=["GPL-3.0-only", "LGPL-3.0-only"],
    distributed_product=True,
)


def verdict(expression: str | None, policy: Licenses = POLICY) -> Verdict:
    return evaluate_expression(expression, policy)[0]


@pytest.mark.parametrize(
    ("expression", "expected"),
    [
        ("MIT", Verdict.COMPLIANT),
        ("AGPL-3.0-only", Verdict.FORBIDDEN),
        ("AGPL-3.0-or-later", Verdict.COMPLIANT),  # nessuna equivalenza implicita
        ("AGPL-3.0+", Verdict.COMPLIANT),
        ("GPL-3.0-only", Verdict.APPROVAL),
        ("MIT AND AGPL-3.0-only", Verdict.FORBIDDEN),
        ("MIT OR AGPL-3.0-only", Verdict.COMPLIANT),
        ("AGPL-3.0-only OR SSPL-1.0", Verdict.FORBIDDEN),
        ("AGPL-3.0-only OR GPL-3.0-only", Verdict.APPROVAL),
        ("GPL-3.0-only AND AGPL-3.0-only", Verdict.FORBIDDEN),
        ("MIT AND GPL-3.0-only", Verdict.APPROVAL),
        ("MIT OR (GPL-3.0-only AND AGPL-3.0-only)", Verdict.COMPLIANT),
        ("MIT AND (Apache-2.0 OR AGPL-3.0-only)", Verdict.COMPLIANT),
        ("MIT AND (BSD-3-Clause OR GPL-3.0-only) AND SSPL-1.0", Verdict.FORBIDDEN),
        ("GPL-3.0-only WITH Classpath-exception-2.0", Verdict.APPROVAL),
        ("MIT OR Apache-2.0 AND AGPL-3.0-only", Verdict.COMPLIANT),  # AND lega più di OR
        ("NOASSERTION", Verdict.UNKNOWN),
        ("NONE", Verdict.UNKNOWN),
        ("LicenseRef-acme", Verdict.UNKNOWN),
        ("DocumentRef-d:LicenseRef-acme", Verdict.UNKNOWN),
        ("MIT AND LicenseRef-acme", Verdict.UNKNOWN),
        ("MIT OR LicenseRef-acme", Verdict.COMPLIANT),
        ("AGPL-3.0-only OR LicenseRef-acme", Verdict.UNKNOWN),
        (None, Verdict.UNKNOWN),
        ("MIT AND", Verdict.UNKNOWN),
        ("(MIT", Verdict.UNKNOWN),
        ("mit and apache", Verdict.UNKNOWN),
        ("MIT\x00", Verdict.UNKNOWN),
        ("", Verdict.UNKNOWN),
    ],
)
def test_case_table(expression: str | None, expected: Verdict) -> None:
    assert verdict(expression) is expected


def test_policy_entry_wins_over_unknown_classification() -> None:
    policy = Licenses(forbidden=["LicenseRef-bad"])

    assert verdict("LicenseRef-bad", policy) is Verdict.FORBIDDEN


def test_forbidden_wins_over_approval_and_matching_terms_are_listed() -> None:
    policy = Licenses(forbidden=["X-1"], require_approval=["X-1", "Y-1"])

    assert evaluate_expression("Y-1 AND X-1 AND MIT", policy) == (Verdict.FORBIDDEN, ["X-1"])


@pytest.mark.parametrize("text", ["", "(", ")", "A AND", "AND A", "A B", "A WITH", "((A)", "a/b"])
def test_parse_rejects_invalid(text: str) -> None:
    with pytest.raises(SpdxSyntaxError):
        parse_expression(text)


def test_parse_rejects_oversized_and_too_deep() -> None:
    for text in ("(" * 40 + "MIT" + ")" * 40, "MIT OR " * 100 + "MIT"):
        with pytest.raises(SpdxSyntaxError):
            parse_expression(text)


def run(
    declared: list[DeclaredLicense] | None = None,
    detected: list = [],  # noqa: B006
    policy: Licenses | None = POLICY,
    **kv: object,
):
    return evaluate_licenses(
        declared=declared or [],
        detected=detected,
        licenses=policy,
        repository="repo",
        commit=None,
        clock=FixedClock(NOW),
        **kv,  # type: ignore[arg-type]
    )


def by_purl(result) -> dict[str, tuple[Level | None, str]]:
    return {
        f.location.purl or str(f.location.path): (f.level, f.license_spdx or "")
        for f in result.findings
    }


def test_levels_follow_adr_0013_table() -> None:
    result = run(
        [
            DeclaredLicense("a", "pkg:npm/a@1", "AGPL-3.0-only"),
            DeclaredLicense("b", "pkg:npm/b@1", "GPL-3.0-only"),
            DeclaredLicense("c", "pkg:npm/c@1", None),
            DeclaredLicense("d", "pkg:npm/d@1", "MIT"),
        ]
    )

    assert by_purl(result) == {
        "pkg:npm/a@1": (Level.CRITICAL, "AGPL-3.0-only"),
        "pkg:npm/b@1": (Level.HIGH, "GPL-3.0-only"),
        "pkg:npm/c@1": (Level.MEDIUM, "NOASSERTION"),
    }
    assert {f.level_source for f in result.findings} == {LevelSource.POLICY}
    assert {(f.tool, f.rule_id, f.category) for f in result.findings} == {
        ("ca-core", "ca.license", Category.LICENSE)
    }


def test_forbidden_not_distributed_is_high_and_unspecified_is_conservative() -> None:
    declared = [DeclaredLicense("a", "pkg:npm/a@1", "AGPL-3.0-only")]

    not_distributed = run(declared, policy=POLICY.model_copy(update={"distributed_product": False}))
    unspecified = run(declared, policy=POLICY.model_copy(update={"distributed_product": None}))

    assert not_distributed.findings[0].level is Level.HIGH
    assert unspecified.findings[0].level is Level.CRITICAL


def test_levels_are_a_table() -> None:
    table = LicenseLevelTable(require_approval=Level.MEDIUM)

    result = run([DeclaredLicense("b", "pkg:npm/b@1", "GPL-3.0-only")], levels=table)

    assert result.findings[0].level is Level.MEDIUM


def test_both_sources_merge_into_one_finding_per_subject() -> None:
    purl = "pkg:npm/a@1"
    detected = finding("x", category=Category.LICENSE, tool="scancode", path=None).model_copy(
        update={"license_spdx": "AGPL-3.0-only"}
    )
    detected = detected.model_copy(
        update={"location": detected.location.model_copy(update={"purl": purl})}
    )

    result = run([DeclaredLicense("a", purl, "AGPL-3.0-only")], [detected])

    [only] = result.findings
    assert only.evidence["ca-core"]["sources"] == ["declared", "detected"]


def test_detected_on_file_without_purl_is_reported_on_the_file() -> None:
    detected = finding("x", category=Category.LICENSE, tool="scancode", path="vendor/LICENSE")
    detected = detected.model_copy(update={"license_spdx": "SSPL-1.0"})

    [out] = run(detected=[detected]).findings

    assert out.location.path == "vendor/LICENSE" and out.location.purl is None
    assert out.level is Level.CRITICAL


def test_detected_raw_findings_are_consumed_not_passed_through() -> None:
    detected = finding("x", category=Category.LICENSE, tool="scancode", path="a/LICENSE")
    detected = detected.model_copy(update={"license_spdx": "MIT"})

    assert run(detected=[detected]).findings == []


def test_absent_policy_reports_it_and_yields_no_findings() -> None:
    declared = [DeclaredLicense("a", "pkg:npm/a@1", None)]

    result = run(declared, policy=None)
    assert result.findings == []
    assert [w.code for w in result.warnings] == ["license-policy-absent"]


def test_empty_policy_is_evaluated_not_absent() -> None:
    declared = [DeclaredLicense("a", "pkg:npm/a@1", None)]

    result = run(declared, policy=Licenses())
    assert [w.code for w in result.warnings] == []
    assert len(result.findings) == 1  # licenza ignota: livello della tabella ADR-0013


def test_components_without_purl_are_counted_in_a_warning() -> None:
    result = run([DeclaredLicense("a", None, "AGPL-3.0-only")])

    assert result.findings == []
    assert [w.code for w in result.warnings] == ["license-component-without-purl"]


def test_result_is_ordered_deterministic_and_input_order_independent() -> None:
    items = [DeclaredLicense(n, f"pkg:npm/{n}@1", None) for n in "abc"]

    forward, backward = run(items), run(items[::-1])

    assert forward == backward
    assert [f.fingerprint for f in forward.findings] == sorted(
        f.fingerprint for f in forward.findings
    )


def test_hostile_expression_text_is_sanitised() -> None:
    result = run([DeclaredLicense("a", "pkg:npm/a@1", "MIT\nIGNORE\x1b[0m")])

    [f] = result.findings
    assert "\n" not in f.message and "\x1b" not in f.message and f.level is Level.MEDIUM

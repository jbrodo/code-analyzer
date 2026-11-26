"""K-13: valutazione del gate (IPOTESI D-0009-A)."""

from builders import finding, plugin, report

from ca_core.models.finding import Category, Level, Status
from ca_core.pipeline.gate import DEFAULT_BLOCK_ON, evaluate_gate

C, H, M, L = Level.CRITICAL, Level.HIGH, Level.MEDIUM, Level.LOW


def with_level(n: str, level: Level | None, **kv: object):
    return finding(n, level=level, **kv)  # type: ignore[arg-type]


def test_default_blocks_critical_and_high() -> None:
    r = report([with_level("a", C), with_level("b", H), with_level("c", M), with_level("d", L)])

    result = evaluate_gate(r)

    assert (result.exit_code, result.block_on_source) == (1, "default")
    assert {b.level for b in result.blocking} == {C, H}
    assert DEFAULT_BLOCK_ON == (C, H)


def test_only_lower_levels_passes() -> None:
    assert evaluate_gate(report([with_level("c", M), with_level("d", L)])).exit_code == 0
    assert evaluate_gate(report()).exit_code == 0


def test_precedence_cli_then_config_then_default() -> None:
    r = report(
        [with_level("a", C), with_level("m", M)],
        gate={"mode": "all", "effective_mode": "all", "block_on": ["medio"]},
    )

    from_config = evaluate_gate(r)
    from_cli = evaluate_gate(r, fail_on=[C])

    assert (from_config.block_on_source, [b.level for b in from_config.blocking]) == ("config", [M])
    assert (from_cli.block_on_source, [b.level for b in from_cli.blocking]) == ("cli", [C])


def test_explicit_empty_list_blocks_nothing() -> None:
    r = report([with_level("a", C)])

    assert evaluate_gate(r, fail_on=[]).exit_code == 0


def test_accepted_findings_are_excluded() -> None:
    accepted = with_level("a", C, status=Status.ACCEPTED)

    assert evaluate_gate(report([accepted])).exit_code == 0
    assert evaluate_gate(report([accepted, with_level("b", H)])).exit_code == 1


def test_warn_on_lists_but_does_not_block() -> None:
    r = report(
        [with_level("m", M)],
        gate={"mode": "all", "effective_mode": "all", "warn_on": ["medio"]},
    )

    result = evaluate_gate(r)

    assert result.exit_code == 0 and [w.level for w in result.warned] == [M]


def partial() -> dict[str, object]:
    return {
        "status": "partial",
        "plugins": [plugin("trivy", outcome="failed", failure="timeout")],
    }


def test_partial_scan_exits_2_even_with_blocking_findings() -> None:
    r = report([with_level("a", C)], **partial())

    result = evaluate_gate(r)

    assert result.exit_code == 2 and result.reasons == ["partial-scan"]


def test_allow_partial_evaluates_what_is_there_and_reports_the_reason() -> None:
    clean = evaluate_gate(report(**partial()), allow_partial=True)
    dirty = evaluate_gate(report([with_level("a", C)], **partial()), allow_partial=True)

    assert (clean.exit_code, clean.reasons) == (0, ["partial-scan"])
    assert (dirty.exit_code, dirty.reasons) == (1, ["partial-scan"])


def test_signature_skipped_exits_2_without_allow_partial_even_if_complete() -> None:
    r = report([with_level("a", M)], plugins=[plugin(signature="skipped")])

    assert r.status.value == "complete"
    assert evaluate_gate(r).exit_code == 2
    assert evaluate_gate(r).reasons == ["signature-skipped"]
    assert evaluate_gate(r, allow_partial=True).exit_code == 0


def test_finding_without_level_is_an_error_even_with_allow_partial() -> None:
    r = report([with_level("a", None)])

    for allow in (False, True):
        result = evaluate_gate(r, allow_partial=allow)
        assert result.exit_code == 2 and "finding-without-level" in result.reasons


def test_accepted_finding_without_level_is_ignored() -> None:
    r = report([with_level("a", None, status=Status.ACCEPTED)])

    assert evaluate_gate(r).exit_code == 0


def test_result_is_serializable_and_pure() -> None:
    r = report([with_level("a", H, category=Category.SECRET)])
    before = r.model_dump_json()

    result = evaluate_gate(r)

    assert r.model_dump_json() == before
    assert evaluate_gate(r) == result
    assert type(result).model_validate_json(result.model_dump_json()) == result


def pr_report(*states: tuple[str, Level, str]):
    findings = [with_level(n, lv, baseline_state=st) for n, lv, st in states]
    return report(
        findings,
        gate={"mode": "new-findings-only", "effective_mode": "new-findings-only"},
        scan={"kind": "pr", "base_commit": "a" * 40},
        baseline={
            "status": "valid",
            "commit": "a" * 40,
            "source": "ci-artifact",
            "new": sum(s == "new" for _, _, s in states),
            "existing": sum(s == "existing" for _, _, s in states),
        },
    )


def test_new_findings_only_blocks_only_the_new_ones() -> None:
    old_only = evaluate_gate(pr_report(("a", C, "existing")))
    assert (old_only.exit_code, old_only.mode.value) == (0, "new-findings-only")
    mixed = evaluate_gate(pr_report(("a", C, "existing"), ("b", H, "new"), ("c", L, "new")))
    assert mixed.exit_code == 1 and [b.level for b in mixed.blocking] == [H]


def test_new_findings_only_still_exits_2_on_a_partial_scan() -> None:
    bad = plugin("trivy", outcome="failed", failure="timeout")
    r = pr_report(("a", L, "existing")).model_copy(
        update={"status": "partial", "plugins": [plugin_run(bad)]}
    )
    assert evaluate_gate(r).exit_code == 2


def plugin_run(data: dict):
    from ca_core.models.scan_report import PluginRun

    return PluginRun.model_validate(data)

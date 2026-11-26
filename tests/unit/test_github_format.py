"""N-03: commento e annotazioni di GitHub, con contenuto ostile (ADR-0027)."""

import re
from typing import Any

import pytest
from builders import finding, plugin, report

from ca_core.models.finding import BaselineState, Category, Level, Remediation, Status
from ca_core.pipeline.gate import evaluate_gate
from ca_integrations import limits
from ca_integrations.github.format import (
    MARKER,
    ZWSP,
    annotations_for,
    build_check_run,
    build_comment,
    clean_text,
    neutralize,
    selected,
)
from ca_integrations.models import AnnotationLevel, Conclusion

BASE = "a" * 40
HOSTILE = (
    "@octocat #123 org/repo#9 [clic](http://evil.example/x) <img src=x onerror=alert(1)> "
    "http://evil.example www.evil.example a@b.example deadbeef1234 `code` **b** | > # \u202e"
    "\n## Titolo finto\n<!-- code-analyzer:1 --> ![i](http://x/y.png) :+1: &amp; ~~s~~"
)


def pr_report(*items: Any, **kv: Any):
    new = sum(f.baseline_state is BaselineState.NEW for f in items)
    old = sum(f.baseline_state is BaselineState.EXISTING for f in items)
    return report(
        list(items),
        gate={"mode": "new-findings-only", "effective_mode": "new-findings-only"},
        scan={"kind": "pr", "base_commit": BASE},
        baseline={
            "status": "valid",
            "commit": BASE,
            "source": "ci-artifact",
            "new": new,
            "existing": old,
        },
        **kv,
    )


def f(n: str, state: str | None = "new", level: Level = Level.HIGH, **kv: Any):
    return finding(n, level=level, baseline_state=state, **kv)


# --- neutralizzazione ----------------------------------------------------------------------


def test_every_ascii_punctuation_is_escaped_and_nothing_remains_active() -> None:
    text = neutralize(HOSTILE, 2000)
    for marker in ("](http", "http://", "www.", "@octocat", " #123", "deadbeef1234"):
        assert marker not in text
    punctuation = r"[!-/:-@\[-`{-~]"
    leftover = re.sub(r"\\" + punctuation, "", text)
    unescaped = re.findall(punctuation, leftover)
    assert unescaped == []  # ogni segno ASCII è preceduto da un backslash
    assert "\u202e" not in text and "\n" not in text


def test_mentions_and_references_are_broken_by_an_invisible_character() -> None:
    assert neutralize("@user", 50) == "\\@" + ZWSP + "user"
    assert neutralize("#12", 50) == "\\#" + ZWSP + "12"
    assert ZWSP in neutralize("deadbeef1234", 50) and "deadbe" in neutralize("deadbeef1234", 50)


def test_clean_text_removes_controls_and_bidi_and_limits_length() -> None:
    assert clean_text("a\x00b\x1b[31mc\u202ed\r\ne\tf", 100) == "ab[31mcd e f"
    long = clean_text("x" * 500, 20)
    assert len(long) == 20 and long.endswith("…")
    assert clean_text("", 10) == "" and clean_text("   \n ", 10) == ""


@pytest.mark.parametrize("limit", [1, 5, 50])
def test_neutralize_respects_the_limit_before_escaping(limit: int) -> None:
    assert len(clean_text("*" * 100, limit)) <= limit


def test_hostile_content_cannot_forge_the_marker_or_a_heading() -> None:
    title = "x\n<!-- code-analyzer:1 -->\n# Titolo finto"
    comment = build_comment(pr_report(f("a")))
    assert comment.body.startswith(MARKER + "\n")
    hostile = f("b").model_copy(update={"title": title, "message": title})
    body = build_comment(pr_report(hostile)).body
    assert body.count("code-analyzer:") == 1  # il costruttore del modello lo esige
    assert not any(
        line.startswith(("#", "<!--"))
        for line in body.splitlines()[3:]
        if "\\" not in line and not line.startswith("###")
    )


# --- commento ------------------------------------------------------------------------------


def test_only_new_findings_are_listed_with_counts() -> None:
    r = pr_report(f("n"), f("old", "existing"), f("low", level=Level.LOW))
    body = build_comment(r).body
    assert "**2 nuovi**, 1 esistenti, 0 risolti" in body
    assert "r\\-n" in body and "r\\-low" in body and "r\\-old" not in body
    assert body.index("r\\-n") < body.index("r\\-low")  # per livello
    comment = build_comment(r)
    assert (comment.findings_shown, comment.findings_hidden) == (2, 0)


def test_without_a_valid_baseline_the_comment_says_so_and_lists_the_blocking_ones() -> None:
    r = report([finding("b", level=Level.CRITICAL), finding("m", level=Level.MEDIUM)])
    body = build_comment(r).body
    assert "Nessuna baseline valida" in body and "Finding che bloccano (1 di 1)" in body
    assert "r\\-b" in body and "r\\-m" not in body


def test_the_cap_and_the_remainder() -> None:
    items = [f(str(i)) for i in range(30)]
    comment = build_comment(pr_report(*items), max_findings=5)
    assert (comment.findings_shown, comment.findings_hidden) == (5, 25)
    assert "altri 25 non mostrati" in comment.body
    assert build_comment(pr_report(*items), max_findings=0).findings_shown == 0


def test_the_body_stays_under_the_limit_and_never_cuts_a_finding() -> None:
    items = [
        f(str(i)).model_copy(update={"title": "T" * 500, "rule_id": "R" * 500}) for i in range(300)
    ]
    comment = build_comment(pr_report(*items), max_findings=300)
    assert len(comment.body) <= limits.GITHUB_COMMENT_MAX_CHARS
    assert comment.findings_shown + comment.findings_hidden == 300
    assert comment.findings_hidden > 0
    numbered = re.findall(r"^\d+\. ", comment.body, flags=re.M)
    assert len(numbered) == comment.findings_shown


def test_a_correlation_group_is_shown_once_with_all_its_tools() -> None:
    group = "cg1:" + "a" * 16
    one = f("g1", tool="bandit", correlation=group)
    two = f("g2", tool="semgrep", correlation=group).model_copy(update={"rule_id": "r-g2"})
    body = build_comment(pr_report(one, two)).body
    assert len(re.findall(r"^\d+\. ", body, flags=re.M)) == 1
    assert "bandit" in body and "semgrep" in body


def test_remediation_is_shown_as_plain_neutralized_text() -> None:
    fix = Remediation(text="Usare `shlex.quote` @team", source="rule", references=[])
    body = build_comment(pr_report(f("a", remediation=fix))).body
    assert "Correzione: Usare \\`shlex\\.quote\\` \\@" + ZWSP + "team" in body


def test_partial_status_and_warnings_lead_the_comment() -> None:
    bad = plugin("trivy", outcome="failed", failure="timeout")
    r = report(
        [],
        status="partial",
        plugins=[plugin(), bad],
        warnings=[{"code": "baseline-missing", "message": "@all niente #1"}],
    )
    body = build_comment(r).body
    assert "Scansione parziale" in body and "Avviso baseline\\-missing" in body
    assert "@all" not in body and "Nessun finding da mostrare" in body


def test_an_accepted_finding_is_not_listed() -> None:
    accepted = f("a").model_copy(update={"status": Status.ACCEPTED})
    assert selected(pr_report(accepted)) == []


def test_findings_without_location_have_no_position_text() -> None:
    body = build_comment(pr_report(f("a", path=None))).body
    assert "app/run.py" not in body and "r\\-a" in body


def test_no_secret_value_can_appear() -> None:
    secret = finding("s", category=Category.SECRET, level=Level.CRITICAL)
    secret = secret.model_copy(update={"evidence": {"gitleaks": {"secret_like": "NEVER"}}})
    r = pr_report(secret.model_copy(update={"baseline_state": BaselineState.NEW}))
    check = build_check_run(r)
    assert "NEVER" not in build_comment(r).body and "NEVER" not in check.model_dump_json()


# --- check run -----------------------------------------------------------------------------


def test_conclusion_follows_the_gate_function() -> None:
    assert build_check_run(pr_report(f("a"))).conclusion is Conclusion.FAILURE
    assert build_check_run(pr_report(f("a", "existing"))).conclusion is Conclusion.SUCCESS
    bad = plugin("trivy", outcome="failed", failure="timeout")
    partial = report([], status="partial", plugins=[plugin(), bad])
    assert build_check_run(partial).conclusion is Conclusion.NEUTRAL
    r = pr_report(f("a"))
    assert build_check_run(r, gate=evaluate_gate(r, fail_on=[])).conclusion is Conclusion.SUCCESS


def test_annotations_map_levels_and_respect_the_cap() -> None:
    items = [
        f("c", level=Level.CRITICAL),
        f("h", level=Level.HIGH),
        f("m", level=Level.MEDIUM),
        f("l", level=Level.LOW),
    ]
    levels = [a.level for a in annotations_for(items)]
    assert levels == [
        AnnotationLevel.FAILURE,
        AnnotationLevel.FAILURE,
        AnnotationLevel.WARNING,
        AnnotationLevel.NOTICE,
    ]
    many = [f(str(i)) for i in range(80)]
    assert len(annotations_for(many)) == 50 and len(annotations_for(many, 3)) == 3
    assert len(annotations_for(many, 1000)) == limits.GITHUB_ANNOTATIONS_PER_REQUEST


def test_only_located_findings_get_an_annotation_and_the_summary_counts_the_rest() -> None:
    items = [f(str(i)) for i in range(60)] + [f("nopath", path=None)]
    check = build_check_run(pr_report(*items))
    assert len(check.output.annotations) == 50
    assert "Annotazioni: 50 di 60" in check.output.summary


def test_annotation_text_is_clean_and_within_limits() -> None:
    hostile = f("a").model_copy(
        update={"title": "t" * 900 + "\x1b", "message": "m\u202e\x00" * 5000}
    )
    (a,) = annotations_for([hostile])
    assert len(a.title) <= limits.GITHUB_ANNOTATION_TITLE_MAX and "\x1b" not in a.title
    assert "\u202e" not in a.message and "\x00" not in a.message
    assert len(a.message.encode()) <= limits.GITHUB_ANNOTATION_MESSAGE_MAX_BYTES


def test_end_line_is_never_before_the_start_line() -> None:
    item = f("a")
    odd = item.model_copy(
        update={"location": item.location.model_copy(update={"start_line": 9, "end_line": None})}
    )
    (a,) = annotations_for([odd])
    assert (a.start_line, a.end_line) == (9, 9)


def test_check_run_summary_names_the_gate_reasons() -> None:
    bad = plugin("trivy", outcome="failed", failure="timeout")
    check = build_check_run(report([], status="partial", plugins=[plugin(), bad]))
    assert "partial\\-scan" in check.output.summary and check.output.title == "Scansione parziale"

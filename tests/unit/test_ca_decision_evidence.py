"""Selezione dell'evidenza (DE-02): nel dubbio nulla, e nessun segreto piantato nell'evidenza,
negli errori o nei log. I «segreti» si compongono a runtime: nel sorgente non ce ne sono."""

import logging
import re
from typing import Any

import pytest
from pydantic import ValidationError

from ca_core.models.decision import Evidence
from ca_core.models.finding import Finding
from ca_core.models.scan_report import PluginRun, ScanReport
from ca_decision.evidence import packaged_settings, secret_paths, select_evidence
from ca_decision.redaction import MASK, redact

SETTINGS = packaged_settings()
PATH = "app/db.py"
FILES = [PATH, "app/config.py"]


def planted(*parts: str) -> str:
    return "".join(parts)


RANDOM = planted("q7Zp", "L2xV", "9mKd", "R4tB", "8wYc", "N1sF", "6hJg")
AWS = planted("AK", "IA", "Q7ZPL2XV9MKDR4TB")
GITHUB = planted("gh", "p_", RANDOM)
JWT = planted("ey", "Jhbbbbbbb", ".", "eyJzdWIiOiIx", ".", "c2lnbmF0dXJl")
PEM_BODY = planted("MIIEvQIBADAN", "BgkqhkiG9w0BAQEFAASC")
PEM = planted("-----BEGIN ", "PRIVATE KEY-----\n", PEM_BODY, "\n-----END ", "PRIVATE KEY-----")

LEAKS = {
    "aws": (f'key = "{AWS}"', AWS),
    "github": (f"headers = auth({GITHUB!r})", GITHUB),
    "jwt": (f"t = '{JWT}'", JWT),
    "url": (planted("db = 'postgres://app:", "hunter2pass", "@db:5432/x'"), "hunter2pass"),
    "password": (planted('PASSWORD = "', "corretto cavallo", '"'), "corretto cavallo"),
    "dict": (planted("cfg = {'client_secret': '", "abc123xyz", "'}"), "abc123xyz"),
    "annotated": (planted("api_key_live: ", "str = ", f'"{RANDOM}"'), RANDOM),
    "env": (planted("export DB_PASSWORD=", "s3gretissimo"), "s3gretissimo"),
    "bearer": (planted("# Authorization: Bearer ", RANDOM), RANDOM),
    "entropy": (f'value = "{RANDOM}"', RANDOM),
    "pem": (f'KEY = """{PEM}"""', PEM_BODY),
}


def finding(**over: Any) -> Finding:
    data = {
        "id": "sha256:" + "1" * 64,
        "fingerprint": "sha256:" + "1" * 64,
        "category": "sast",
        "rule_id": "B608",
        "tool": "bandit",
        "tools": ["bandit"],
        "title": "B608",
        "message": "Possible SQL injection vector",
        "location": {"repository": "r", "commit": "c" * 40, "path": PATH, "start_line": 30},
        "status": "aperto",
        "first_seen": "2026-11-27T10:00:00Z",
        "last_seen": "2026-11-27T10:00:00Z",
        **over,
    }
    return Finding.model_validate(data)


def secret(path: str, **over: Any) -> Finding:
    location = {"repository": "r", "commit": "c" * 40, "path": path, "start_line": 1}
    return finding(
        category="secret", tool="gitleaks", tools=["gitleaks"], location=location, **over
    )


def report(*findings: Finding, gitleaks: str | None = "ok") -> ScanReport:
    plugins = []
    if gitleaks:
        plugins.append(
            {
                "name": "gitleaks",
                "version": "1.0.0",
                "digest": "sha256:" + "d" * 64,
                "signature": "verified",
                "isolation": "hardened-container",
                "duration_seconds": 1.0,
                "outcome": gitleaks,
                **({"failure": "tool"} if gitleaks == "failed" else {}),
            }
        )
    runs = [PluginRun.model_validate(p) for p in plugins]
    return ScanReport.model_construct(findings=list(findings), plugins=runs)


def source(special: str = "query = build(user)", at: int = 30, total: int = 80) -> str:
    lines = [f"riga_{n} = {n}" for n in range(1, total + 1)]
    lines[at - 1] = special
    return "\n".join(lines)


def select(
    code: str | None = None, the: Finding | None = None, rep: Any = None, **over: Any
) -> Any:
    return select_evidence(
        the or finding(),
        code if code is not None else source(),
        rep or report(),
        over.get("files", FILES),
        over.get("settings", SETTINGS),
    )


def test_a_clean_file_gives_twenty_lines_around_the_marked_one() -> None:
    chosen = select()
    text = chosen.evidence.text
    assert not chosen.evidence.reduced and chosen.redactions == 0
    assert "> 30: query = build(user)" in text
    assert "  10: riga_10 = 10" in text and "  50: riga_50 = 50" in text
    assert "riga_9 " not in text and "riga_51" not in text
    assert text.startswith("Regola: B608 (bandit)\nMessaggio: Possible SQL")


@pytest.mark.parametrize(
    "rep,reason",
    [
        (report(gitleaks=None), "ricerca-segreti-non-disponibile"),
        (report(gitleaks="failed"), "ricerca-segreti-non-disponibile"),
        (report(secret(PATH)), "segreto-nel-file"),
        (report(secret("app/vecchio.py")), "segreto-in-percorso-scomparso"),
    ],
    ids=["not-run", "failed", "secret-in-file", "secret-renamed-away"],
)
def test_in_doubt_no_code_at_all(rep: ScanReport, reason: str) -> None:
    chosen = select(rep=rep)
    assert (chosen.evidence, chosen.withheld) == (None, reason)


def test_a_secret_in_another_existing_file_does_not_block_this_one() -> None:
    assert select(rep=report(secret("app/config.py"))).evidence


@pytest.mark.parametrize("status", ["falso_positivo", "accettato", "risolto"])
def test_a_secret_counts_whatever_its_status(status: str) -> None:
    assert select(rep=report(secret(PATH, status=status))).withheld == "segreto-nel-file"


def test_other_occurrences_of_a_secret_count_too() -> None:
    other = secret("app/config.py", evidence={"occurrences": [{"path": PATH}]})
    assert secret_paths(report(other)) == {PATH, "app/config.py"}
    assert select(rep=report(other)).withheld == "segreto-nel-file"


@pytest.mark.parametrize(
    "the,reason",
    [
        (secret(PATH), "categoria"),
        (finding(category="quality"), "categoria"),
        (finding(rule_id="B105"), "regola-sui-segreti"),
        (finding(location={"repository": "r", "commit": "c", "path": PATH}), "senza-posizione"),
        (
            finding(location={"repository": "r", "commit": "c", "path": PATH, "start_line": 999}),
            "senza-posizione",
        ),
    ],
)
def test_findings_without_evidence(the: Finding, reason: str) -> None:
    assert select(the=the).withheld == reason


@pytest.mark.parametrize("line,hidden", LEAKS.values(), ids=LEAKS.keys())
def test_planted_secrets_do_not_reach_the_evidence_or_the_logs(
    line: str, hidden: str, caplog: pytest.LogCaptureFixture
) -> None:
    code = source(line, at=28)
    with caplog.at_level(logging.DEBUG):
        chosen = select(code, the=finding(message=f"Trovato in {line}"))
    assert chosen.evidence is not None
    assert hidden not in chosen.evidence.text
    assert MASK in chosen.evidence.text
    assert chosen.redactions >= 1
    assert hidden not in repr(chosen) and hidden not in caplog.text


def test_a_key_block_that_starts_above_the_window_is_still_hidden() -> None:
    body = "\n".join(planted("MIIEvQ", f"{n:04d}", "abcdefghij") for n in range(40))
    code = planted("-----BEGIN ", "PRIVATE KEY-----\n", body, "\n-----END PRIVATE KEY-----\n")
    code += source("query = build(user)", at=5)
    line = code.split("\n").index("query = build(user)") + 1
    the = finding(location={"repository": "r", "commit": "c", "path": PATH, "start_line": line})
    chosen = select(code, the=the)
    assert "MIIEvQ" not in chosen.evidence.text
    assert chosen.redactions > 10 and f"{line - 20}: {MASK}" in chosen.evidence.text
    assert f"> {line}: query = build(user)" in chosen.evidence.text


def test_ordinary_code_is_left_alone() -> None:
    code = (
        "token = request.headers.get('Authorization')\n"
        "password = form.cleaned_data['password']\n"
        'label = "Inserisci la password del tuo account"\n'
        "url = 'https://example.org/percorso/molto/lungo'\n"
        "digest = hashlib.md5(key).hexdigest()"
    )
    assert redact(code, SETTINGS) == (code, 0)


def test_only_what_the_engine_sees_is_counted() -> None:
    code = source() + f"\n\n\n{planted('k = ', repr(AWS))}"
    assert select(code).redactions == 0


def test_redaction_keeps_the_line_numbers() -> None:
    code = f"a = 1\nKEY = '''{PEM}'''\nb = 2"
    hidden, count = redact(code, SETTINGS)
    assert count >= 1 and hidden.count("\n") == code.count("\n")


def test_the_window_shrinks_to_fit_and_says_so() -> None:
    small = SETTINGS.model_copy(update={"max_characters": 400})
    chosen = select(settings=small)
    assert chosen.evidence.reduced
    assert len(chosen.evidence.text) <= 400
    assert "> 30:" in chosen.evidence.text


def test_long_lines_are_cut_and_said() -> None:
    chosen = select(source("x = f(" + "a, " * 300 + ")"))
    assert chosen.evidence.reduced and " […]" in chosen.evidence.text


def test_a_finding_too_long_for_the_limit_gets_nothing_not_a_slice() -> None:
    small = SETTINGS.model_copy(update={"max_characters": 200})
    long = finding(
        location={"repository": "r", "commit": "c", "path": PATH, "start_line": 1, "end_line": 80}
    )
    assert select(the=long, settings=small).withheld == "troppo-grande"


def test_validation_errors_do_not_repeat_the_code() -> None:
    with pytest.raises(ValidationError) as failure:
        Evidence(text=RANDOM * 5000, reduced=False)
    assert RANDOM not in str(failure.value)


def test_the_shipped_patterns_compile() -> None:
    for pattern in SETTINGS.redaction_patterns:
        re.compile(pattern, re.MULTILINE)

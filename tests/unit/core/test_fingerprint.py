"""T-01: casi attesi e proprieta del fingerprint `fp1` (ADR-0008). Precede K-04.

Firma attesa di `ca_core.fingerprint` (derivata da ADR-0008; K-04 deve rispettarla).
Tutte le funzioni restituiscono `"sha256:" + <64 hex minuscoli>`.

    compute_fingerprint(kind: str, rule_id: str, tool_family: str,
                        normalized_location: str, component: str) -> str
        sha256("fp1" NUL kind NUL rule_id NUL tool_family NUL normalized_location NUL component)

    context_hash(source: str, start_line: int) -> str            # 64 hex, senza prefisso
    normalize_purl(purl: str) -> str                             # purl senza versione (ADR-0008 §5)
    canonical_vuln_id(ids: Sequence[str]) -> str
        `ids` = unione di ruleId e alias, con duplicati ammessi; lista vuota: ValueError.
        Minimo lessicografico tra i `CVE-`; altrimenti tra i `GHSA-`; altrimenti tra tutti.

    class CodeSite(NamedTuple):
        rule_id, tool, path, context_hash, start_line,
        start_column=None, end_line=None, end_column=None
    assign_occurrences(sites: Sequence[CodeSite]) -> list[int]   # stesso ordine di `sites`

    fingerprint_code(*, rule_id: str, tool: str, path: str, source: str,
                     start_line: int, occurrence: int = 0) -> str          # kind code (sast, iac)
    fingerprint_dependency(*, vuln_ids: Sequence[str], purl: str) -> str   # kind dependency
    fingerprint_license_package(*, spdx: str, purl: str) -> str            # kind license-package
    fingerprint_license_file(*, path: str, spdx: str) -> str               # kind license-file
    fingerprint_secret(*, rule_id: str, path: str, value_sha256: str) -> str  # kind secret
    fingerprint_health(*, plugin: str) -> str                              # kind health

`source` e il testo intero del file, `start_line` e 1-based. `purl` puo contenere la versione:
la funzione la toglie. `occurrence` e l'indice 0-based calcolato da `assign_occurrences`.
Ingressi non validi sollevano ValueError. Formato, bordi, spazi e vettori: ADR-0008,
"Precisazioni per K-04". L'idempotenza della dedup e di K-07, non e qui.
"""

import hashlib
import importlib
import inspect
import re
from types import ModuleType
from typing import Any

import pytest

try:
    from hypothesis import given
    from hypothesis import strategies as st

    HAS_HYPOTHESIS = True
except ImportError:  # dipendenza di sviluppo da aggiungere; senza, le proprieta sono saltate
    HAS_HYPOTHESIS = False

FP_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def fp() -> ModuleType:
    """Import tardivo: la raccolta di pytest non dipende da K-04."""
    return importlib.import_module("ca_core.fingerprint")


def expected_hash(kind: str, rule_id: str, family: str, location: str, component: str) -> str:
    raw = "\0".join(["fp1", kind, rule_id, family, location, component])
    return "sha256:" + hashlib.sha256(raw.encode()).hexdigest()


SOURCE = "\n".join(
    ["import os", "", "def run(cmd):", "    os.system(cmd)", "    return 1", "", "print(1)"]
)
CODE = {"rule_id": "B605", "tool": "bandit", "path": "app/run.py", "start_line": 4}


# --- formula -------------------------------------------------------------------------------


def test_formula_golden_vector() -> None:
    value = fp().compute_fingerprint("dependency", "CVE-2021-44228", "vuln", "", "pkg:pypi/django")
    assert value == "sha256:98b5df0045686e5c39554558d7dded0e258f3001ee19a4fc7b8237339c74b128"


def test_formula_separates_fields_with_nul() -> None:
    m = fp()
    # "ab"+"c" e "a"+"bc" non devono collidere: il separatore NUL e parte dell'algoritmo.
    assert m.compute_fingerprint("code", "ab", "c", "", "") != m.compute_fingerprint(
        "code", "a", "bc", "", ""
    )


# --- kind: code ----------------------------------------------------------------------------


def test_code_format_and_determinism() -> None:
    a = fp().fingerprint_code(source=SOURCE, **CODE)
    assert FP_RE.match(a)
    assert a == fp().fingerprint_code(source=SOURCE, **CODE)


def test_code_stable_when_lines_are_inserted_above() -> None:
    shifted = "# a\n# b\n# c\n" + SOURCE
    a = fp().fingerprint_code(source=SOURCE, **CODE)
    b = fp().fingerprint_code(source=shifted, **{**CODE, "start_line": 7})
    assert a == b


def test_code_crlf_equals_lf() -> None:
    a = fp().fingerprint_code(source=SOURCE, **CODE)
    b = fp().fingerprint_code(source=SOURCE.replace("\n", "\r\n"), **CODE)
    assert a == b


def test_code_collapses_runs_of_spaces() -> None:
    a = fp().fingerprint_code(source=SOURCE, **CODE)
    b = fp().fingerprint_code(source=SOURCE.replace("def run", "def    run"), **CODE)
    assert a == b


@pytest.mark.parametrize(
    ("neighbour", "new_text"),
    [(3, "def run(cmd, extra):"), (5, "    return 2")],
    ids=["line-before-start", "line-after-start"],
)
def test_code_context_is_one_line_before_and_after(neighbour: int, new_text: str) -> None:
    # Lettura letterale di "2 righe attorno": riga iniziale (4), una prima (3), una dopo (5).
    lines = SOURCE.split("\n")
    lines[neighbour - 1] = new_text
    a = fp().fingerprint_code(source=SOURCE, **CODE)
    b = fp().fingerprint_code(source="\n".join(lines), **CODE)
    assert a != b


def test_code_ignores_lines_beyond_context() -> None:
    lines = SOURCE.split("\n")
    lines[0] = "import sys"  # due righe sopra la riga 4: fuori dal contesto
    a = fp().fingerprint_code(source=SOURCE, **CODE)
    b = fp().fingerprint_code(source="\n".join(lines), **CODE)
    assert a == b


@pytest.mark.parametrize(
    "change",
    [{"rule_id": "B602"}, {"tool": "semgrep"}, {"path": "app/other.py"}],
    ids=["rule", "tool-family", "path"],
)
def test_code_depends_on_rule_tool_and_path(change: dict[str, Any]) -> None:
    a = fp().fingerprint_code(source=SOURCE, **CODE)
    assert a != fp().fingerprint_code(source=SOURCE, **{**CODE, **change})


def test_code_signature_matches_declared_one() -> None:
    sig = inspect.signature(fp().fingerprint_code)
    assert {"rule_id", "tool", "path", "source", "start_line", "occurrence"} <= set(sig.parameters)


def test_code_duplicates_are_distinguished_by_occurrence() -> None:
    dup = "x = 1\nos.system(a)\ny = 2\n\nx = 1\nos.system(a)\ny = 2\n"
    first = fp().fingerprint_code(source=dup, **{**CODE, "start_line": 2, "occurrence": 0})
    second = fp().fingerprint_code(source=dup, **{**CODE, "start_line": 6, "occurrence": 1})
    assert first != second


def test_code_occurrence_is_stable_when_duplicates_shift() -> None:
    dup = "x = 1\nos.system(a)\ny = 2\n\nx = 1\nos.system(a)\ny = 2\n"
    a = fp().fingerprint_code(source=dup, **{**CODE, "start_line": 6, "occurrence": 1})
    b = fp().fingerprint_code(
        source="# nuova\n" + dup, **{**CODE, "start_line": 7, "occurrence": 1}
    )
    assert a == b


# --- kind: dependency ----------------------------------------------------------------------


def test_dependency_matches_formula() -> None:
    value = fp().fingerprint_dependency(vuln_ids=["CVE-2021-44228"], purl="pkg:pypi/django")
    assert value == expected_hash("dependency", "CVE-2021-44228", "vuln", "", "pkg:pypi/django")


def test_dependency_osv_ghsa_and_trivy_cve_merge() -> None:
    # osv-scanner riporta GHSA con alias CVE, trivy il solo CVE: stesso problema (§4.2, §1).
    osv = fp().fingerprint_dependency(
        vuln_ids=["GHSA-jfh8-c2jp-5v3q", "CVE-2021-44228"], purl="pkg:maven/a/b@2.14.0"
    )
    trivy = fp().fingerprint_dependency(vuln_ids=["CVE-2021-44228"], purl="pkg:maven/a/b@2.14.0")
    assert osv == trivy


def test_dependency_ignores_version_in_purl() -> None:
    a = fp().fingerprint_dependency(vuln_ids=["CVE-2021-1"], purl="pkg:pypi/django@3.0")
    b = fp().fingerprint_dependency(vuln_ids=["CVE-2021-1"], purl="pkg:pypi/django@4.2")
    assert a == b == fp().fingerprint_dependency(vuln_ids=["CVE-2021-1"], purl="pkg:pypi/django")


def test_dependency_differs_by_component_and_vulnerability() -> None:
    base = fp().fingerprint_dependency(vuln_ids=["CVE-2021-1"], purl="pkg:pypi/django")
    assert base != fp().fingerprint_dependency(vuln_ids=["CVE-2021-1"], purl="pkg:pypi/flask")
    assert base != fp().fingerprint_dependency(vuln_ids=["CVE-2021-2"], purl="pkg:pypi/django")


@pytest.mark.parametrize(
    ("ids", "expected"),
    [
        (["GHSA-aaaa-aaaa-aaaa", "CVE-2022-2", "CVE-2021-9"], "CVE-2021-9"),
        (["CVE-2021-10", "CVE-2021-2"], "CVE-2021-10"),  # lessicografico, non numerico
        (["PYSEC-1", "GHSA-bbbb-bbbb-bbbb", "GHSA-aaaa-aaaa-aaaa"], "GHSA-aaaa-aaaa-aaaa"),
        (["PYSEC-2022-1"], "PYSEC-2022-1"),
        (["GHSA-aaaa-aaaa-aaaa"], "GHSA-aaaa-aaaa-aaaa"),
    ],
    ids=["cve-over-ghsa", "lexicographic", "ghsa-no-cve", "scanner-id-only", "single-ghsa"],
)
def test_canonical_vuln_id(ids: list[str], expected: str) -> None:
    assert fp().canonical_vuln_id(ids) == expected


def test_dependency_new_cve_assigned_to_ghsa_changes_fingerprint() -> None:
    # Rischio accettato in ADR-0008: documentato come comportamento atteso.
    before = fp().fingerprint_dependency(vuln_ids=["GHSA-aaaa-aaaa-aaaa"], purl="pkg:pypi/x")
    after = fp().fingerprint_dependency(
        vuln_ids=["GHSA-aaaa-aaaa-aaaa", "CVE-2024-1"], purl="pkg:pypi/x"
    )
    assert before != after


# --- kind: license-package -----------------------------------------------------------------


def test_license_package_matches_formula() -> None:
    value = fp().fingerprint_license_package(spdx="GPL-3.0-only", purl="pkg:npm/left-pad@1.3.0")
    assert value == expected_hash(
        "license-package", "ca.license", "license", "GPL-3.0-only", "pkg:npm/left-pad"
    )


def test_license_package_ignores_version_and_differs_by_license() -> None:
    a = fp().fingerprint_license_package(spdx="MIT", purl="pkg:npm/x@1")
    assert a == fp().fingerprint_license_package(spdx="MIT", purl="pkg:npm/x@2")
    assert a != fp().fingerprint_license_package(spdx="GPL-3.0-only", purl="pkg:npm/x@1")


# --- kind: license-file --------------------------------------------------------------------


def test_license_file_format_and_dependence() -> None:
    a = fp().fingerprint_license_file(path="vendor/LICENSE", spdx="AGPL-3.0-only")
    assert FP_RE.match(a)
    assert a == fp().fingerprint_license_file(path="vendor/LICENSE", spdx="AGPL-3.0-only")
    assert a != fp().fingerprint_license_file(path="vendor/LICENSE", spdx="MIT")
    assert a != fp().fingerprint_license_file(path="other/LICENSE", spdx="AGPL-3.0-only")


def test_license_file_differs_from_license_package() -> None:
    # Il kind e nell'hash: nessuna collisione tra le due forme di licenza.
    assert fp().fingerprint_license_file(path="a", spdx="MIT") != (
        fp().fingerprint_license_package(spdx="MIT", purl="pkg:npm/a")
    )


# --- kind: secret --------------------------------------------------------------------------

H1 = hashlib.sha256(b"FAKE-SECRET-NOT-REAL-1").hexdigest()
H2 = hashlib.sha256(b"FAKE-SECRET-NOT-REAL-2").hexdigest()
SECRET = {"rule_id": "generic-api-key", "path": "config/settings.py", "value_sha256": H1}


def test_secret_format_and_determinism() -> None:
    a = fp().fingerprint_secret(**SECRET)
    assert FP_RE.match(a) and a == fp().fingerprint_secret(**SECRET)


def test_secret_same_value_in_several_commits_is_one_fingerprint() -> None:
    # ADR-0008/0012: il commit non entra nel fingerprint; la firma non lo accetta nemmeno.
    params = set(inspect.signature(fp().fingerprint_secret).parameters)
    assert not params & {"commit", "commit_sha", "author", "email", "date", "line", "start_line"}
    assert fp().fingerprint_secret(**SECRET) == fp().fingerprint_secret(**SECRET)


@pytest.mark.parametrize(
    "change",
    [{"value_sha256": H2}, {"path": "config/other.py"}, {"rule_id": "aws-access-token"}],
    ids=["value", "path", "rule"],
)
def test_secret_depends_on_value_path_and_rule(change: dict[str, str]) -> None:
    assert fp().fingerprint_secret(**SECRET) != fp().fingerprint_secret(**{**SECRET, **change})


def test_secret_never_embeds_the_value() -> None:
    # Il fingerprint dipende dall'hash, non dal valore: nessuna sottostringa del segreto finto.
    assert "FAKE-SECRET" not in fp().fingerprint_secret(**SECRET)


# --- kind: coverage ------------------------------------------------------------------------


def test_coverage_matches_formula_and_ignores_lines() -> None:
    value = fp().fingerprint_coverage(rule_id="ca.coverage.low-file-coverage", path="pkg/calc.py")
    assert value == expected_hash(
        "coverage", "ca.coverage.low-file-coverage", "coverage", "pkg/calc.py", ""
    )
    assert value.startswith("sha256:") and len(value) == 71


def test_coverage_differs_by_rule_and_path() -> None:
    one = fp().fingerprint_coverage(rule_id="r", path="a.py")
    assert one != fp().fingerprint_coverage(rule_id="r", path="b.py")
    assert one != fp().fingerprint_coverage(rule_id="s", path="a.py")


@pytest.mark.parametrize("path", ["", "/a.py", "a/../b.py", "a\x00b.py", "./a.py"])
def test_coverage_rejects_unsafe_paths(path: str) -> None:
    with pytest.raises(ValueError):
        fp().fingerprint_coverage(rule_id="r", path=path)


# --- kind: health --------------------------------------------------------------------------


def test_health_matches_formula() -> None:
    value = fp().fingerprint_health(plugin="semgrep")
    assert value == expected_hash("health", "ca.scanner-not-run", "ca", "semgrep", "")
    assert value == "sha256:420f683681ccc6f1e2f3b0eeff0ff631b8de2a6739fdd4510622e594472f1d48"


def test_health_differs_by_plugin() -> None:
    assert fp().fingerprint_health(plugin="semgrep") != fp().fingerprint_health(plugin="bandit")


# --- vettori golden di ADR-0008 -------------------------------------------------------------

CTX_4 = "d47f4091a596c49743162cdd10baf905a2daad5b9b517314147244f25c4f69f4"
CTX_1 = "d6f34ecc0e2af7242bf9d77a21f32dcb32be709e96f7088e74978eb0671c0eb2"
CTX_7 = "a31c6181c7365adfa4b7a3dae5bc3b028126f1a973e89a9cffc2698f79322d3a"
CTX_EMPTY = "75a11da44c802486bc6f65640aa48a730f0f684c5c07a42ba3cd1735eb3fb070"


def test_h1_is_the_documented_fake_secret_hash() -> None:
    assert H1 == "aa9d997ccd858516b21e6eddf65825e622e807a34586cc3cd25074cb6bbd657b"


@pytest.mark.parametrize(
    ("source", "line", "expected"),
    [
        (SOURCE, 4, CTX_4),
        (SOURCE, 1, CTX_1),
        (SOURCE, 7, CTX_7),
        (SOURCE + "\n", 7, CTX_7),
        ("", 1, CTX_EMPTY),
    ],
    ids=["middle", "first-line", "last-line", "last-line-trailing-lf", "empty-source"],
)
def test_context_hash_golden(source: str, line: int, expected: str) -> None:
    assert fp().context_hash(source, line) == expected


def test_code_golden_vectors() -> None:
    a = fp().fingerprint_code(source=SOURCE, occurrence=0, **CODE)
    b = fp().fingerprint_code(source=SOURCE, occurrence=1, **CODE)
    assert a == "sha256:187c77673925b2ef1adb137c936008f2234866b63ff8b84725553f7def7c0ed0"
    assert b == "sha256:74a89bf93e4398895f7ad8826dabc244a2a78fef6cd46a359e60da1a5abf54bb"


def test_secret_golden_vector() -> None:
    assert fp().fingerprint_secret(**SECRET) == (
        "sha256:8f72eb4d0df8835149ac43ef26fd85bd4f4b3a0f2111ebf7bffd7cf51d315af0"
    )


def test_license_file_golden_vector() -> None:
    value = fp().fingerprint_license_file(path="vendor/LICENSE", spdx="AGPL-3.0-only")
    assert value == "sha256:5afd24e0e77943f5191a42cf963b79809a63d97b88db65ea042905de805e3ebf"


# --- bordi del file, spazi, CR, BOM --------------------------------------------------------


@pytest.mark.parametrize(
    "line", [1, 7, 8, 100], ids=["first", "last", "past-end-1", "far-past-end"]
)
def test_context_hash_edges_do_not_raise(line: int) -> None:
    assert re.fullmatch(r"[0-9a-f]{64}", fp().context_hash(SOURCE, line))


def test_context_hash_past_end_uses_empty_lines() -> None:
    assert fp().context_hash(SOURCE, 100) == fp().context_hash("", 1)


@pytest.mark.parametrize("line", [0, -1])
def test_context_hash_start_line_below_one_is_value_error(line: int) -> None:
    with pytest.raises(ValueError):
        fp().context_hash(SOURCE, line)


def test_context_ignores_indentation_and_tabs() -> None:
    reindented = SOURCE.replace("    os.system", "\t\tos.system").replace("    return", "  return")
    assert fp().context_hash(reindented, 4) == fp().context_hash(SOURCE, 4)


def test_context_nbsp_is_not_a_space() -> None:
    nbsp = SOURCE.replace("def run", "def\u00a0run")
    assert fp().context_hash(nbsp, 4) != fp().context_hash(SOURCE, 4)
    assert fp().context_hash(nbsp, 3) != fp().context_hash(SOURCE, 3)


@pytest.mark.parametrize("sep", ["\x0b", "\x0c"], ids=["vt", "ff"])
def test_context_vt_and_ff_are_spaces_not_line_breaks(sep: str) -> None:
    # Si divide solo su LF: VT e FF dentro una riga non spostano i numeri di riga.
    with_sep = SOURCE.replace("os.system(cmd)", f"os.system(cmd){sep}# x")
    assert fp().context_hash(with_sep, 5) == fp().context_hash(
        SOURCE.replace("os.system(cmd)", "os.system(cmd) # x"), 5
    )


def test_context_lone_cr_equals_lf() -> None:
    assert fp().context_hash(SOURCE.replace("\n", "\r"), 4) == CTX_4


def test_context_leading_bom_is_ignored() -> None:
    assert fp().context_hash("\ufeff" + SOURCE, 4) == CTX_4
    assert fp().context_hash("\ufeff" + SOURCE, 1) == CTX_1


# --- assign_occurrences --------------------------------------------------------------------


def _site(
    sl: int, sc: int | None = None, el: int | None = None, ec: int | None = None, **kw: str
) -> Any:
    base = {"rule_id": "r", "tool": "t", "path": "p.py", "context_hash": "c" * 64}
    return fp().CodeSite(
        **{**base, **kw}, start_line=sl, start_column=sc, end_line=el, end_column=ec
    )


def _example_sites() -> list[Any]:
    return [_site(20, 1, 20, 5), _site(2, 9, 2, 12), _site(2, 1, 2, 5), _site(20, 1, 20, 5)]


def test_assign_occurrences_adr_example() -> None:
    assert fp().assign_occurrences(_example_sites()) == [2, 1, 0, 2]


@pytest.mark.parametrize("order", [[3, 2, 1, 0], [1, 3, 0, 2], [2, 0, 3, 1]])
def test_assign_occurrences_does_not_depend_on_input_order(order: list[int]) -> None:
    sites = _example_sites()
    base = fp().assign_occurrences(sites)
    permuted = fp().assign_occurrences([sites[i] for i in order])
    assert permuted == [base[i] for i in order]


def test_assign_occurrences_groups_by_key_and_handles_missing_columns() -> None:
    sites = [
        _site(5),
        _site(5, rule_id="other"),
        _site(5, tool="other"),
        _site(5, path="q.py"),
        _site(5, context_hash="d" * 64),
        _site(3),
    ]
    # Solo il primo e l'ultimo condividono la chiave: righe 3 < 5.
    assert fp().assign_occurrences(sites) == [1, 0, 0, 0, 0, 0]
    assert fp().assign_occurrences([]) == []


def test_assign_occurrences_missing_end_line_means_start_line() -> None:
    assert fp().assign_occurrences([_site(4, 1, 4, 9), _site(4, 1, None, 9)]) == [0, 0]


# --- normalize_purl ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("purl", "expected"),
    [
        ("pkg:pypi/Django_Foo.bar@1", "pkg:pypi/django-foo-bar"),
        ("pkg:npm/%40angular/core@1.0", "pkg:npm/%40angular/core"),
        ("pkg:npm/@Angular/Core", "pkg:npm/%40angular/core"),
        ("pkg:npm/left-pad@1.3.0?foo=bar#sub/x", "pkg:npm/left-pad"),
        ("pkg:deb/debian/libc6@2.31?arch=amd64&distro=debian-11", "pkg:deb/debian/libc6"),
        (
            "pkg:golang/google.golang.org/genproto@v0.0.1#googleapis/api",
            "pkg:golang/google.golang.org/genproto",
        ),
        (
            "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0",
            "pkg:maven/org.apache.logging.log4j/log4j-core",
        ),
    ],
    ids=[
        "pypi",
        "npm-scope-encoded",
        "npm-scope-raw",
        "npm-qualifier-subpath",
        "deb",
        "golang",
        "maven",
    ],
)
def test_normalize_purl_table(purl: str, expected: str) -> None:
    assert fp().normalize_purl(purl) == expected


@pytest.mark.parametrize("purl", ["a", "", "pkg:", "npm/left-pad", "pkg:npm/a b"])
def test_normalize_purl_rejects_invalid(purl: str) -> None:
    with pytest.raises(ValueError):
        fp().normalize_purl(purl)


# --- alias: nuovi casi ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("ids", "expected"),
    [
        (["PYSEC-2022-190", "BIT-django-2022-28346"], "BIT-django-2022-28346"),
        (["CVE-2020-28500", "GHSA-29mw-wpgm-hmr9", "CVE-2020-28500"], "CVE-2020-28500"),
    ],
    ids=["min-among-unknown-prefixes", "duplicates-allowed"],
)
def test_canonical_vuln_id_new_cases(ids: list[str], expected: str) -> None:
    assert fp().canonical_vuln_id(ids) == expected


def test_canonical_vuln_id_empty_is_value_error() -> None:
    with pytest.raises(ValueError):
        fp().canonical_vuln_id([])


# --- ingressi non validi -------------------------------------------------------------------


@pytest.mark.parametrize(
    "change",
    [
        {"rule_id": "a\0b"},
        {"rule_id": ""},
        {"tool": ""},
        {"tool": "a\0b"},
        {"path": "/abs/run.py"},
        {"path": "../run.py"},
        {"path": "a/../run.py"},
        {"path": "a//run.py"},
        {"path": "./run.py"},
        {"path": "a\0b.py"},
        {"path": ""},
        {"start_line": 0},
    ],
    ids=[
        "nul-rule",
        "empty-rule",
        "empty-tool",
        "nul-tool",
        "absolute",
        "dotdot-lead",
        "dotdot-mid",
        "empty-segment",
        "dot-segment",
        "nul-path",
        "empty-path",
        "line-zero",
    ],
)
def test_code_invalid_inputs_are_value_error(change: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        fp().fingerprint_code(source=SOURCE, **{**CODE, **change})


@pytest.mark.parametrize(
    "change",
    [
        {"rule_id": "a\0b"},
        {"path": "/abs/settings.py"},
        {"path": "../settings.py"},
        {"value_sha256": H1.upper()},
    ],
    ids=["nul-rule", "absolute-path", "dotdot-path", "uppercase-hash"],
)
def test_secret_invalid_inputs_are_value_error(change: dict[str, str]) -> None:
    with pytest.raises(ValueError):
        fp().fingerprint_secret(**{**SECRET, **change})


def test_other_kinds_reject_invalid_inputs() -> None:
    m = fp()
    with pytest.raises(ValueError):
        m.fingerprint_dependency(vuln_ids=[], purl="pkg:pypi/x")
    with pytest.raises(ValueError):
        m.fingerprint_dependency(vuln_ids=["CVE-2021-1"], purl="x")
    with pytest.raises(ValueError):
        m.fingerprint_license_file(path="/abs/LICENSE", spdx="MIT")
    with pytest.raises(ValueError):
        m.fingerprint_license_file(path="LICENSE", spdx="")
    with pytest.raises(ValueError):
        m.fingerprint_license_package(spdx="MIT", purl="a")
    with pytest.raises(ValueError):
        m.fingerprint_health(plugin="")
    with pytest.raises(ValueError):
        m.compute_fingerprint("code\0x", "r", "t", "", "")


# --- proprieta (hypothesis) ----------------------------------------------------------------

if HAS_HYPOTHESIS:
    word = st.text(alphabet="abcdefghij_=()", min_size=1, max_size=8)
    code_line = st.lists(word, min_size=1, max_size=4).map(" ".join)
    code_lines = st.lists(code_line, min_size=3, max_size=12)

    @given(lines=code_lines, above=st.lists(code_line, max_size=20), data=st.data())
    def test_prop_fingerprint_stable_under_line_shift(
        lines: list[str], above: list[str], data: st.DataObject
    ) -> None:
        idx = data.draw(st.integers(min_value=1, max_value=len(lines) - 2))  # 0-based, con vicini
        base = {"rule_id": "r", "tool": "t", "path": "p.py"}
        a = fp().fingerprint_code(source="\n".join(lines), start_line=idx + 1, **base)
        b = fp().fingerprint_code(
            source="\n".join([*above, *lines]), start_line=idx + 1 + len(above), **base
        )
        assert a == b

    @given(lines=code_lines, data=st.data())
    def test_prop_crlf_equals_lf(lines: list[str], data: st.DataObject) -> None:
        idx = data.draw(st.integers(min_value=1, max_value=len(lines) - 2))
        base = {"rule_id": "r", "tool": "t", "path": "p.py", "start_line": idx + 1}
        lf = fp().fingerprint_code(source="\n".join(lines), **base)
        crlf = fp().fingerprint_code(source="\r\n".join(lines), **base)
        assert lf == crlf

    @given(
        lines=code_lines,
        widths=st.lists(st.integers(1, 4), min_size=1, max_size=50),
        data=st.data(),
    )
    def test_prop_space_runs_are_collapsed(
        lines: list[str], widths: list[int], data: st.DataObject
    ) -> None:
        idx = data.draw(st.integers(min_value=1, max_value=len(lines) - 2))
        it = iter(widths * 100)
        widened = [re.sub(" ", lambda _m: " " * next(it), line) for line in lines]
        base = {"rule_id": "r", "tool": "t", "path": "p.py", "start_line": idx + 1}
        a = fp().fingerprint_code(source="\n".join(lines), **base)
        b = fp().fingerprint_code(source="\n".join(widened), **base)
        assert a == b

    @given(occ_a=st.integers(0, 20), occ_b=st.integers(0, 20))
    def test_prop_occurrence_separates_duplicates(occ_a: int, occ_b: int) -> None:
        src = "a\nb\nc\n"
        base = {"rule_id": "r", "tool": "t", "path": "p.py", "source": src, "start_line": 2}
        a = fp().fingerprint_code(occurrence=occ_a, **base)
        b = fp().fingerprint_code(occurrence=occ_b, **base)
        assert (a == b) == (occ_a == occ_b)

    cves = st.from_regex(r"CVE-20[0-9]{2}-[0-9]{4,6}", fullmatch=True)
    ghsas = st.from_regex(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", fullmatch=True)

    @given(
        cve_ids=st.lists(cves, min_size=1, max_size=4),
        ghsa_ids=st.lists(ghsas, max_size=3),
        data=st.data(),
    )
    def test_prop_alias_order_and_ghsa_do_not_change_canonical_id(
        cve_ids: list[str], ghsa_ids: list[str], data: st.DataObject
    ) -> None:
        mixed = data.draw(st.permutations([*cve_ids, *ghsa_ids]))
        assert fp().canonical_vuln_id(mixed) == min(cve_ids)
        purl = "pkg:pypi/x"
        assert fp().fingerprint_dependency(vuln_ids=mixed, purl=purl) == (
            fp().fingerprint_dependency(vuln_ids=cve_ids, purl=purl)
        )

    @given(
        ghsa_ids=st.lists(ghsas, min_size=1, max_size=4, unique=True),
        data=st.data(),
    )
    def test_prop_ghsa_only_picks_lexicographic_first(
        ghsa_ids: list[str], data: st.DataObject
    ) -> None:
        assert fp().canonical_vuln_id(data.draw(st.permutations(ghsa_ids))) == min(ghsa_ids)

    @given(
        value=st.text(min_size=1, max_size=40),
        path=st.from_regex(r"[a-z]{1,6}(/[a-z]{1,6}){0,3}\.py", fullmatch=True),
    )
    def test_prop_secret_fingerprint_is_valid_and_value_hash_driven(value: str, path: str) -> None:
        h = hashlib.sha256(value.encode()).hexdigest()
        a = fp().fingerprint_secret(rule_id="r", path=path, value_sha256=h)
        assert FP_RE.match(a)
        assert a == fp().fingerprint_secret(rule_id="r", path=path, value_sha256=h)
else:

    @pytest.mark.skip(reason="hypothesis non installato: aggiungerlo al gruppo dev")
    def test_properties_require_hypothesis() -> None:
        raise AssertionError("non raggiungibile")

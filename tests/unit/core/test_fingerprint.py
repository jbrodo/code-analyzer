"""T-01: casi attesi e proprieta del fingerprint `fp1` (ADR-0008). Precede K-04.

Firma attesa di `ca_core.fingerprint` (derivata da ADR-0008; K-04 deve rispettarla).
Tutte le funzioni restituiscono `"sha256:" + <64 hex minuscoli>`.

    compute_fingerprint(kind: str, rule_id: str, tool_family: str,
                        normalized_location: str, component: str) -> str
        sha256("fp1" NUL kind NUL rule_id NUL tool_family NUL normalized_location NUL component)

    canonical_vuln_id(ids: Sequence[str]) -> str
        `ids` = tutti gli identificatori noti (id dello scanner e alias).
        Primo CVE in ordine lessicografico; altrimenti primo GHSA; altrimenti `ids[0]`.

    fingerprint_code(*, rule_id: str, tool: str, path: str, source: str,
                     start_line: int, occurrence: int = 0) -> str          # kind code (sast, iac)
    fingerprint_dependency(*, vuln_ids: Sequence[str], purl: str) -> str   # kind dependency
    fingerprint_license_package(*, spdx: str, purl: str) -> str            # kind license-package
    fingerprint_license_file(*, path: str, spdx: str) -> str               # kind license-file
    fingerprint_secret(*, rule_id: str, path: str, value_sha256: str) -> str  # kind secret
    fingerprint_health(*, plugin: str) -> str                              # kind health

`source` e il testo intero del file, `start_line` e 1-based. `purl` puo contenere la versione:
la funzione la toglie. `occurrence` e l'indice 0-based tra finding con stessa regola e stesso
hash di contesto nel file: chi lo assegna e un punto aperto (vedi report T-01).

Ogni test che dipende dall'implementazione e `xfail(strict=True, raises=ImportError)`: con K-04
presente un XPASS fa fallire la suite e ricorda di togliere il marcatore; un errore di
comportamento resta un fallimento vero (non viene assorbito dall'xfail).
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
K04 = "K-04: ca_core.fingerprint non esiste ancora (ADR-0008)"
needs_k04 = pytest.mark.xfail(strict=True, raises=ImportError, reason=K04)


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


@needs_k04
def test_formula_golden_vector() -> None:
    value = fp().compute_fingerprint("dependency", "CVE-2021-44228", "vuln", "", "pkg:pypi/django")
    assert value == "sha256:98b5df0045686e5c39554558d7dded0e258f3001ee19a4fc7b8237339c74b128"


@needs_k04
def test_formula_separates_fields_with_nul() -> None:
    m = fp()
    # "ab"+"c" e "a"+"bc" non devono collidere: il separatore NUL e parte dell'algoritmo.
    assert m.compute_fingerprint("code", "ab", "c", "", "") != m.compute_fingerprint(
        "code", "a", "bc", "", ""
    )


# --- kind: code ----------------------------------------------------------------------------


@needs_k04
def test_code_format_and_determinism() -> None:
    a = fp().fingerprint_code(source=SOURCE, **CODE)
    assert FP_RE.match(a)
    assert a == fp().fingerprint_code(source=SOURCE, **CODE)


@needs_k04
def test_code_stable_when_lines_are_inserted_above() -> None:
    shifted = "# a\n# b\n# c\n" + SOURCE
    a = fp().fingerprint_code(source=SOURCE, **CODE)
    b = fp().fingerprint_code(source=shifted, **{**CODE, "start_line": 7})
    assert a == b


@needs_k04
def test_code_crlf_equals_lf() -> None:
    a = fp().fingerprint_code(source=SOURCE, **CODE)
    b = fp().fingerprint_code(source=SOURCE.replace("\n", "\r\n"), **CODE)
    assert a == b


@needs_k04
def test_code_collapses_runs_of_spaces() -> None:
    a = fp().fingerprint_code(source=SOURCE, **CODE)
    b = fp().fingerprint_code(source=SOURCE.replace("def run", "def    run"), **CODE)
    assert a == b


@needs_k04
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


@needs_k04
def test_code_ignores_lines_beyond_context() -> None:
    lines = SOURCE.split("\n")
    lines[0] = "import sys"  # due righe sopra la riga 4: fuori dal contesto
    a = fp().fingerprint_code(source=SOURCE, **CODE)
    b = fp().fingerprint_code(source="\n".join(lines), **CODE)
    assert a == b


@needs_k04
@pytest.mark.parametrize(
    "change",
    [{"rule_id": "B602"}, {"tool": "semgrep"}, {"path": "app/other.py"}],
    ids=["rule", "tool-family", "path"],
)
def test_code_depends_on_rule_tool_and_path(change: dict[str, Any]) -> None:
    a = fp().fingerprint_code(source=SOURCE, **CODE)
    assert a != fp().fingerprint_code(source=SOURCE, **{**CODE, **change})


@needs_k04
def test_code_signature_matches_declared_one() -> None:
    # Il valore completo non e verificabile contro la formula: il formato di
    # `normalized_location` (separatori, hash del contesto) non e definito da ADR-0008.
    sig = inspect.signature(fp().fingerprint_code)
    assert {"rule_id", "tool", "path", "source", "start_line", "occurrence"} <= set(sig.parameters)


@needs_k04
def test_code_duplicates_are_distinguished_by_occurrence() -> None:
    dup = "x = 1\nos.system(a)\ny = 2\n\nx = 1\nos.system(a)\ny = 2\n"
    first = fp().fingerprint_code(source=dup, **{**CODE, "start_line": 2, "occurrence": 0})
    second = fp().fingerprint_code(source=dup, **{**CODE, "start_line": 6, "occurrence": 1})
    assert first != second


@needs_k04
def test_code_occurrence_is_stable_when_duplicates_shift() -> None:
    dup = "x = 1\nos.system(a)\ny = 2\n\nx = 1\nos.system(a)\ny = 2\n"
    a = fp().fingerprint_code(source=dup, **{**CODE, "start_line": 6, "occurrence": 1})
    b = fp().fingerprint_code(
        source="# nuova\n" + dup, **{**CODE, "start_line": 7, "occurrence": 1}
    )
    assert a == b


# --- kind: dependency ----------------------------------------------------------------------


@needs_k04
def test_dependency_matches_formula() -> None:
    value = fp().fingerprint_dependency(vuln_ids=["CVE-2021-44228"], purl="pkg:pypi/django")
    assert value == expected_hash("dependency", "CVE-2021-44228", "vuln", "", "pkg:pypi/django")


@needs_k04
def test_dependency_osv_ghsa_and_trivy_cve_merge() -> None:
    # osv-scanner riporta GHSA con alias CVE, trivy il solo CVE: stesso problema (§4.2, §1).
    osv = fp().fingerprint_dependency(
        vuln_ids=["GHSA-jfh8-c2jp-5v3q", "CVE-2021-44228"], purl="pkg:maven/a/b@2.14.0"
    )
    trivy = fp().fingerprint_dependency(vuln_ids=["CVE-2021-44228"], purl="pkg:maven/a/b@2.14.0")
    assert osv == trivy


@needs_k04
def test_dependency_ignores_version_in_purl() -> None:
    a = fp().fingerprint_dependency(vuln_ids=["CVE-2021-1"], purl="pkg:pypi/django@3.0")
    b = fp().fingerprint_dependency(vuln_ids=["CVE-2021-1"], purl="pkg:pypi/django@4.2")
    assert a == b == fp().fingerprint_dependency(vuln_ids=["CVE-2021-1"], purl="pkg:pypi/django")


@needs_k04
def test_dependency_differs_by_component_and_vulnerability() -> None:
    base = fp().fingerprint_dependency(vuln_ids=["CVE-2021-1"], purl="pkg:pypi/django")
    assert base != fp().fingerprint_dependency(vuln_ids=["CVE-2021-1"], purl="pkg:pypi/flask")
    assert base != fp().fingerprint_dependency(vuln_ids=["CVE-2021-2"], purl="pkg:pypi/django")


@needs_k04
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


@needs_k04
def test_dependency_new_cve_assigned_to_ghsa_changes_fingerprint() -> None:
    # Rischio accettato in ADR-0008: documentato come comportamento atteso.
    before = fp().fingerprint_dependency(vuln_ids=["GHSA-aaaa-aaaa-aaaa"], purl="pkg:pypi/x")
    after = fp().fingerprint_dependency(
        vuln_ids=["GHSA-aaaa-aaaa-aaaa", "CVE-2024-1"], purl="pkg:pypi/x"
    )
    assert before != after


# --- kind: license-package -----------------------------------------------------------------


@needs_k04
def test_license_package_matches_formula() -> None:
    value = fp().fingerprint_license_package(spdx="GPL-3.0-only", purl="pkg:npm/left-pad@1.3.0")
    assert value == expected_hash(
        "license-package", "ca.license", "license", "GPL-3.0-only", "pkg:npm/left-pad"
    )


@needs_k04
def test_license_package_ignores_version_and_differs_by_license() -> None:
    a = fp().fingerprint_license_package(spdx="MIT", purl="pkg:npm/x@1")
    assert a == fp().fingerprint_license_package(spdx="MIT", purl="pkg:npm/x@2")
    assert a != fp().fingerprint_license_package(spdx="GPL-3.0-only", purl="pkg:npm/x@1")


# --- kind: license-file --------------------------------------------------------------------


@needs_k04
def test_license_file_format_and_dependence() -> None:
    a = fp().fingerprint_license_file(path="vendor/LICENSE", spdx="AGPL-3.0-only")
    assert FP_RE.match(a)
    assert a == fp().fingerprint_license_file(path="vendor/LICENSE", spdx="AGPL-3.0-only")
    assert a != fp().fingerprint_license_file(path="vendor/LICENSE", spdx="MIT")
    assert a != fp().fingerprint_license_file(path="other/LICENSE", spdx="AGPL-3.0-only")


@needs_k04
def test_license_file_differs_from_license_package() -> None:
    # Il kind e nell'hash: nessuna collisione tra le due forme di licenza.
    assert fp().fingerprint_license_file(path="a", spdx="MIT") != (
        fp().fingerprint_license_package(spdx="MIT", purl="a")
    )


# --- kind: secret --------------------------------------------------------------------------

H1 = hashlib.sha256(b"FAKE-SECRET-NOT-REAL-1").hexdigest()
H2 = hashlib.sha256(b"FAKE-SECRET-NOT-REAL-2").hexdigest()
SECRET = {"rule_id": "generic-api-key", "path": "config/settings.py", "value_sha256": H1}


@needs_k04
def test_secret_format_and_determinism() -> None:
    a = fp().fingerprint_secret(**SECRET)
    assert FP_RE.match(a) and a == fp().fingerprint_secret(**SECRET)


@needs_k04
def test_secret_same_value_in_several_commits_is_one_fingerprint() -> None:
    # ADR-0008/0012: il commit non entra nel fingerprint; la firma non lo accetta nemmeno.
    params = set(inspect.signature(fp().fingerprint_secret).parameters)
    assert not params & {"commit", "commit_sha", "author", "email", "date", "line", "start_line"}
    assert fp().fingerprint_secret(**SECRET) == fp().fingerprint_secret(**SECRET)


@needs_k04
@pytest.mark.parametrize(
    "change",
    [{"value_sha256": H2}, {"path": "config/other.py"}, {"rule_id": "aws-access-token"}],
    ids=["value", "path", "rule"],
)
def test_secret_depends_on_value_path_and_rule(change: dict[str, str]) -> None:
    assert fp().fingerprint_secret(**SECRET) != fp().fingerprint_secret(**{**SECRET, **change})


@needs_k04
def test_secret_never_embeds_the_value() -> None:
    # Il fingerprint dipende dall'hash, non dal valore: nessuna sottostringa del segreto finto.
    assert "FAKE-SECRET" not in fp().fingerprint_secret(**SECRET)


# --- kind: health --------------------------------------------------------------------------


@needs_k04
def test_health_matches_formula() -> None:
    value = fp().fingerprint_health(plugin="semgrep")
    assert value == expected_hash("health", "ca.scanner-not-run", "ca", "semgrep", "")
    assert value == "sha256:420f683681ccc6f1e2f3b0eeff0ff631b8de2a6739fdd4510622e594472f1d48"


@needs_k04
def test_health_differs_by_plugin() -> None:
    assert fp().fingerprint_health(plugin="semgrep") != fp().fingerprint_health(plugin="bandit")


# --- proprieta (hypothesis) ----------------------------------------------------------------

if HAS_HYPOTHESIS:
    word = st.text(alphabet="abcdefghij_=()", min_size=1, max_size=8)
    code_line = st.lists(word, min_size=1, max_size=4).map(" ".join)
    code_lines = st.lists(code_line, min_size=3, max_size=12)

    @needs_k04
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

    @needs_k04
    @given(lines=code_lines, data=st.data())
    def test_prop_crlf_equals_lf(lines: list[str], data: st.DataObject) -> None:
        idx = data.draw(st.integers(min_value=1, max_value=len(lines) - 2))
        base = {"rule_id": "r", "tool": "t", "path": "p.py", "start_line": idx + 1}
        lf = fp().fingerprint_code(source="\n".join(lines), **base)
        crlf = fp().fingerprint_code(source="\r\n".join(lines), **base)
        assert lf == crlf

    @needs_k04
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

    @needs_k04
    @given(occ_a=st.integers(0, 20), occ_b=st.integers(0, 20))
    def test_prop_occurrence_separates_duplicates(occ_a: int, occ_b: int) -> None:
        src = "a\nb\nc\n"
        base = {"rule_id": "r", "tool": "t", "path": "p.py", "source": src, "start_line": 2}
        a = fp().fingerprint_code(occurrence=occ_a, **base)
        b = fp().fingerprint_code(occurrence=occ_b, **base)
        assert (a == b) == (occ_a == occ_b)

    cves = st.from_regex(r"CVE-20[0-9]{2}-[0-9]{4,6}", fullmatch=True)
    ghsas = st.from_regex(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", fullmatch=True)

    @needs_k04
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

    @needs_k04
    @given(
        ghsa_ids=st.lists(ghsas, min_size=1, max_size=4, unique=True),
        data=st.data(),
    )
    def test_prop_ghsa_only_picks_lexicographic_first(
        ghsa_ids: list[str], data: st.DataObject
    ) -> None:
        assert fp().canonical_vuln_id(data.draw(st.permutations(ghsa_ids))) == min(ghsa_ids)

    @needs_k04
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

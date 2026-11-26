"""K-04: fattore E secondo ADR-0022 (valori dalla configurazione di scoring)."""

import json

import pytest
from builders import finding

from ca_core.models.finding import Category, Location
from ca_core.models.scan_report import ServiceContext, ServiceValue
from ca_core.models.scoring_config import ScoringConfig
from ca_core.scoring.base import ScoringContext
from ca_core.scoring.config import default_bytes, load_default
from ca_core.scoring.exposure import factor_e, is_test_path, purl_package
from ca_core.scoring.reach import NoReachability, ReachResult, ReachState

R, T, N, U = (
    ReachState.REACHABLE,
    ReachState.TEST_ONLY,
    ReachState.NOT_REACHABLE,
    ReachState.UNKNOWN,
)
CONFIG = load_default()


class Fake:
    """Una `Reachability` a tabelle, per provare E senza costruire un grafo."""

    def __init__(
        self,
        modules: dict[str, ReachResult] | None = None,
        packages: dict[str, ReachResult] | None = None,
        dependencies: dict[tuple[str, str], ReachResult] | None = None,
    ) -> None:
        self.modules, self.packages, self.dependencies = (
            modules or {},
            packages or {},
            dependencies or {},
        )

    def module(self, path: str) -> ReachResult | None:
        return self.modules.get(path)

    def package(self, path: str) -> ReachResult | None:
        return self.packages.get(path)

    def dependency(self, ecosystem: str, name: str) -> ReachResult:
        return self.dependencies.get(
            (ecosystem, name), ReachResult(U, reason="nessun-import-corrispondente")
        )


def service(exposed: bool | None, source: str = "catalog") -> ServiceContext:
    return ServiceContext(
        tier=ServiceValue(value=None, source="default"),
        internet_facing=ServiceValue(
            value=exposed, source=source if exposed is not None else "default"
        ),  # type: ignore[arg-type]
    )


def ctx(
    reach: object, exposed: bool | None = None, config: ScoringConfig = CONFIG
) -> ScoringContext:
    return ScoringContext(config=config, service=service(exposed), reachability=reach)  # type: ignore[arg-type]


def code(path: str | None = "app/x.py", category: Category = Category.SAST):
    return finding("x", category=category, path=path)


# --- la tabella di ADR-0022 -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("state", "exposed", "expected"),
    [
        (R, True, 1.0),
        (R, False, 0.6),
        (R, None, 0.6),  # esposizione assente: come interno, non meno
        (U, True, 0.3),
        (U, False, 0.3),
        (U, None, 0.3),
        (T, True, 0.2),
        (N, True, 0.2),
        (N, None, 0.2),
    ],
)
def test_e_table(state: ReachState, exposed: bool | None, expected: float) -> None:
    reach = Fake(
        modules={"app/x.py": ReachResult(state, entrypoint="app/main.py" if state is R else None)}
    )
    assert factor_e(code(), ctx(reach, exposed)).value == expected


def test_evidence_records_state_entrypoint_exposure_and_source() -> None:
    reach = Fake(modules={"app/x.py": ReachResult(R, entrypoint="app/main.py")})
    factor = factor_e(code(), ctx(reach, True))
    assert factor.evidence == {
        "rule": "modulo",
        "reachability": "raggiungibile",
        "entrypoint": "app/main.py",
        "reason": None,
        "exposure": {"value": True, "source": "catalog"},
    }


def test_unknown_reason_is_declared() -> None:
    factor = factor_e(
        code(), ctx(Fake(modules={"app/x.py": ReachResult(U, reason="nessun-entrypoint")}))
    )
    assert factor.evidence["reason"] == "nessun-entrypoint" and factor.value == 0.3


def test_every_value_comes_from_the_configuration() -> None:
    data = json.loads(default_bytes())
    data["e"] = {
        "reachable_exposed": 0.9,
        "reachable_internal": 0.5,
        "reachable_exposure_unknown": 0.4,
        "unknown": 0.25,
        "not_reachable_or_test": 0.1,
    }
    other = ScoringConfig.model_validate(data)
    assert factor_e(code(), ctx(Fake({"app/x.py": ReachResult(R)}), True, other)).value == 0.9
    assert factor_e(code(), ctx(Fake({"app/x.py": ReachResult(R)}), False, other)).value == 0.5
    assert factor_e(code(), ctx(Fake({"app/x.py": ReachResult(R)}), None, other)).value == 0.4
    assert factor_e(code(), ctx(Fake({"app/x.py": ReachResult(U)}), None, other)).value == 0.25
    assert factor_e(code(), ctx(Fake({"app/x.py": ReachResult(N)}), None, other)).value == 0.1


# --- finding senza modulo --------------------------------------------------------------------


def test_a_file_that_is_not_a_module_counts_as_reachable() -> None:
    result = factor_e(code("infra/main.tf", Category.IAC), ctx(Fake(), True))
    assert result.value == 1.0 and result.evidence["reason"] == "senza-modulo"


def test_a_file_that_is_not_a_module_under_a_test_path_is_02() -> None:
    result = factor_e(code("tests/fixtures/app.tf", Category.IAC), ctx(Fake(), True))
    assert result.value == 0.2 and result.evidence["reason"] == "percorso-di-test"


def test_a_finding_without_a_path_is_reachable() -> None:
    assert factor_e(code(None, Category.HEALTH), ctx(Fake(), False)).value == 0.6


def test_without_a_graph_a_module_finding_is_unknown_and_says_why() -> None:
    result = factor_e(code(), ScoringContext(config=CONFIG))
    assert result.value == 0.3 and result.evidence["reason"] == "grafo-assente"


def test_test_path_rules_match_the_extractor() -> None:
    assert is_test_path("tests/a.py") and is_test_path("src/__tests__/a.ts")
    assert is_test_path("pkg/test_a.py") and is_test_path("a_test.py") and is_test_path("a.spec.ts")
    assert not is_test_path("app/contest.py") and not is_test_path("src/latest/a.py")


# --- dipendenze -------------------------------------------------------------------------------


def dep(purl: str | None, category: Category = Category.DEPENDENCY):
    return finding("d", category=category, path="requirements.txt").model_copy(
        update={"location": Location(repository="repo", path="requirements.txt", purl=purl)}
    )


def test_a_dependency_takes_the_usage_state_of_its_package() -> None:
    reach = Fake(dependencies={("pypi", "django"): ReachResult(R, entrypoint="app/main.py")})
    factor = factor_e(dep("pkg:pypi/django@3.2.1"), ctx(reach, True))
    assert factor.value == 1.0 and factor.evidence["rule"] == "dipendenza"


def test_a_license_on_a_component_is_treated_as_the_dependency() -> None:
    reach = Fake(dependencies={("npm", "@scope/pkg"): ReachResult(T)})
    assert (
        factor_e(dep("pkg:npm/%40scope/pkg@1.0.0", Category.LICENSE), ctx(reach, True)).value == 0.2
    )


def test_a_dependency_nobody_imports_is_unknown_not_unused() -> None:
    assert factor_e(dep("pkg:pypi/urllib3@1"), ctx(Fake(), True)).value == 0.3


@pytest.mark.parametrize(
    "purl", ["pkg:cargo/serde@1", "pkg:maven/a/b@1", "not-a-purl", "pkg:pypi/"]
)
def test_a_purl_that_is_not_npm_or_pypi_is_unknown(purl: str) -> None:
    result = factor_e(dep(purl), ctx(Fake(), True))
    assert result.value == 0.3 and result.evidence["reason"] == "purl-non-supportato"


def test_purl_parsing() -> None:
    assert purl_package("pkg:pypi/Django@3.2") == ("pypi", "Django")
    assert purl_package("pkg:npm/%40scope/pkg@1") == ("npm", "@scope/pkg")
    assert purl_package("pkg:npm/lodash@4?x=1#y") == ("npm", "lodash")
    assert purl_package(None) is None


# --- più membri -------------------------------------------------------------------------------


def smell(members: list[str], path: str = "a.py"):
    return finding("s", category=Category.ARCHITECTURE, tool="ca-graph", path=path).model_copy(
        update={"evidence": {"ca-graph": {"members": members, "size": len(members)}}}
    )


def test_a_finding_on_several_members_takes_the_best_state() -> None:
    reach = Fake(modules={"a.py": ReachResult(N), "b.py": ReachResult(R, entrypoint="m.py")})
    factor = factor_e(smell(["a.py", "b.py"]), ctx(reach, True))
    assert factor.value == 1.0 and factor.evidence["rule"] == "membri"


def test_package_members_are_looked_up_as_directories() -> None:
    reach = Fake(packages={"pkg": ReachResult(R, entrypoint="m.py")})
    assert factor_e(smell(["pkg"], "pkg"), ctx(reach, False)).value == 0.6


def test_members_that_resolve_to_nothing_follow_the_no_module_rule() -> None:
    assert factor_e(smell(["gone.py"]), ctx(Fake(), True)).value == 1.0


def test_no_reachability_object_is_all_unknown() -> None:
    none = NoReachability()
    assert none.module("a") == ReachResult(U, reason="grafo-assente")
    assert none.package("a") == ReachResult(U, reason="grafo-assente")

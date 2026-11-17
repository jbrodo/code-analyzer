"""G-12: raggiungibilità dei moduli e uso delle dipendenze (ADR-0022), su grafi scritti a mano."""

from pathlib import Path
from typing import Any

import pytest
from graph_builders import extract

from ca_core.models.graph import Graph
from ca_core.scoring.reach import NoReachability, ReachResult, ReachState, best
from ca_graph import import_names
from ca_graph.reachability import GraphReachability

R, T, N, U = (
    ReachState.REACHABLE,
    ReachState.TEST_ONLY,
    ReachState.NOT_REACHABLE,
    ReachState.UNKNOWN,
)


def mod(path: str, language: str = "python", **kv: Any) -> dict[str, Any]:
    return {"path": path, "language": language, "parse": "completa", **kv}


def edge(source: str, target: str, **kv: Any) -> dict[str, Any]:
    return {"source": source, "target": target, "imports": 1, "confidence": "dichiarato", **kv}


def entry(path: str) -> dict[str, Any]:
    return {"path": path, "kind": "main-module", "confidence": "dedotto"}


def graph(
    modules: list[dict[str, Any]],
    edges: list[dict[str, Any]] = (),  # type: ignore[assignment]
    entrypoints: list[dict[str, Any]] = (),  # type: ignore[assignment]
    externals: list[dict[str, Any]] = (),  # type: ignore[assignment]
    unresolved: dict[str, int] | None = None,
) -> GraphReachability:
    document = {
        "version": 1,
        "modules": sorted(modules, key=lambda m: m["path"]),
        "externals": sorted(externals, key=lambda e: (e["ecosystem"], e["name"])),
        "edges": sorted(
            edges,
            key=lambda e: (e["source"], e["external"] if "external" in e else False, e["target"]),
        ),
        "entrypoints": sorted(entrypoints, key=lambda e: (e["path"], e["kind"])),
        "stats": {"files_parsed": len(modules), "unresolved": unresolved or {}},
        "history": {"status": "assente", "window_days": 90},
    }
    return GraphReachability(Graph.model_validate(document))


def state(reach: GraphReachability, path: str) -> ReachState:
    result = reach.module(path)
    assert result is not None
    return result.state


BASIC = graph(
    [mod("app/main.py"), mod("app/a.py"), mod("app/b.py"), mod("app/orphan.py")],
    [edge("app/main.py", "app/a.py"), edge("app/a.py", "app/b.py")],
    [entry("app/main.py")],
)


def test_entrypoint_and_what_it_imports_are_reachable_with_the_nearest_entrypoint() -> None:
    assert state(BASIC, "app/main.py") == R
    assert state(BASIC, "app/b.py") == R
    assert BASIC.module("app/b.py") == ReachResult(R, entrypoint="app/main.py")


def test_a_complete_graph_can_say_not_reachable() -> None:
    assert state(BASIC, "app/orphan.py") == N


def test_a_path_that_is_not_a_module_is_none_so_the_caller_decides() -> None:
    assert BASIC.module("infra/main.tf") is None


def test_type_only_edges_are_not_followed_but_dynamic_ones_are() -> None:
    reach = graph(
        [mod("m.py"), mod("typed.py"), mod("lazy.py")],
        [edge("m.py", "typed.py", type_only=True), edge("m.py", "lazy.py", dynamic=True)],
        [entry("m.py")],
    )
    assert state(reach, "lazy.py") == R
    assert state(reach, "typed.py") == N


def test_test_files_are_test_only_and_so_is_what_only_they_reach() -> None:
    reach = graph(
        [mod("main.py"), mod("lib.py"), mod("tests/t.py", test=True), mod("helper.py")],
        [edge("tests/t.py", "lib.py"), edge("tests/t.py", "helper.py")],
        [entry("main.py")],
    )
    assert state(reach, "tests/t.py") == T
    assert state(reach, "helper.py") == T  # raggiunto solo da un test
    assert state(reach, "lib.py") == T


def test_reached_by_both_an_entrypoint_and_a_test_is_reachable() -> None:
    reach = graph(
        [mod("main.py"), mod("lib.py"), mod("tests/t.py", test=True)],
        [edge("main.py", "lib.py"), edge("tests/t.py", "lib.py")],
        [entry("main.py")],
    )
    assert state(reach, "lib.py") == R


def test_a_test_file_is_never_an_entrypoint() -> None:
    reach = graph(
        [mod("main.py"), mod("lib.py"), mod("tests/t.py", test=True)],
        [edge("tests/t.py", "lib.py")],
        [entry("tests/t.py"), entry("main.py")],
    )
    assert state(reach, "lib.py") == T


def test_no_entrypoint_for_the_language_means_unknown_never_not_reachable() -> None:
    reach = graph([mod("lib.py"), mod("a.py")], [edge("a.py", "lib.py")], [])
    assert reach.module("lib.py") == ReachResult(U, reason="nessun-entrypoint")


def test_each_language_family_needs_its_own_entrypoint() -> None:
    reach = graph(
        [mod("main.py"), mod("x.py"), mod("src/a.ts", "typescript"), mod("src/b.ts", "typescript")],
        [],
        [entry("main.py")],
    )
    assert state(reach, "x.py") == N
    assert reach.module("src/b.ts") == ReachResult(U, reason="nessun-entrypoint")


def test_typescript_javascript_and_tsx_are_one_family() -> None:
    reach = graph(
        [mod("src/i.js", "javascript"), mod("src/v.tsx", "tsx"), mod("src/u.ts", "typescript")],
        [edge("src/i.js", "src/v.tsx")],
        [entry("src/i.js")],
    )
    assert state(reach, "src/v.tsx") == R
    assert state(reach, "src/u.ts") == N


@pytest.mark.parametrize("key", ["computed", "missing", "outside_workspace", "config_extends"])
def test_any_unresolved_import_makes_unreached_modules_unknown(key: str) -> None:
    reach = graph([mod("main.py"), mod("orphan.py")], [], [entry("main.py")], unresolved={key: 1})
    assert reach.module("orphan.py") == ReachResult(U, reason="import-non-risolti")
    assert state(reach, "main.py") == R  # ciò che è raggiunto lo resta


def test_a_missing_declared_entrypoint_counts_as_an_unresolved_import() -> None:
    reach = graph(
        [mod("main.py"), mod("orphan.py")],
        [],
        [entry("main.py")],
        unresolved={"entrypoint_missing": 1},
    )
    assert state(reach, "orphan.py") == U


def test_a_partially_parsed_file_makes_the_language_unknown_for_unreached_modules() -> None:
    reach = graph(
        [mod("main.py"), mod("orphan.py"), mod("broken.py", parse="parziale")],
        [],
        [entry("main.py")],
    )
    assert reach.module("orphan.py") == ReachResult(U, reason="file-analizzato-in-parte")
    assert state(reach, "main.py") == R


def test_nearest_entrypoint_wins_and_ties_go_to_the_first_path() -> None:
    reach = graph(
        [mod("a_main.py"), mod("z_main.py"), mod("mid.py"), mod("leaf.py")],
        [
            edge("a_main.py", "mid.py"),
            edge("mid.py", "leaf.py"),
            edge("z_main.py", "leaf.py"),
        ],
        [entry("a_main.py"), entry("z_main.py")],
    )
    assert reach.module("leaf.py") == ReachResult(R, entrypoint="z_main.py")  # distanza 1 contro 2
    tie = graph(
        [mod("a_main.py"), mod("z_main.py"), mod("x.py")],
        [edge("z_main.py", "x.py"), edge("a_main.py", "x.py")],
        [entry("z_main.py"), entry("a_main.py")],
    )
    assert tie.module("x.py") == ReachResult(R, entrypoint="a_main.py")


def test_cycles_do_not_loop() -> None:
    reach = graph(
        [mod("main.py"), mod("a.py"), mod("b.py")],
        [edge("main.py", "a.py"), edge("a.py", "b.py"), edge("b.py", "a.py")],
        [entry("main.py")],
    )
    assert state(reach, "b.py") == R


# --- dipendenze ----------------------------------------------------------------------------


def with_dependency(importer_states: str) -> GraphReachability:
    """`main` raggiunge `used`; `orphan` e un test importano pacchetti esterni."""
    return graph(
        [mod("main.py"), mod("used.py"), mod("orphan.py"), mod("tests/t.py", test=True)],
        [
            edge("main.py", "used.py"),
            edge("used.py", "requests", external=True),
            edge("tests/t.py", "pytest", external=True),
            edge("orphan.py", "yaml", external=True),
        ],
        [entry("main.py")],
        externals=[
            {"name": "pytest", "ecosystem": "pypi"},
            {"name": "requests", "ecosystem": "pypi"},
            {"name": "yaml", "ecosystem": "pypi"},
        ],
    )


def test_a_package_imported_by_a_reachable_module_is_reachable() -> None:
    assert with_dependency("").dependency("pypi", "requests").state == R


def test_a_package_imported_only_by_tests_is_test_only() -> None:
    assert with_dependency("").dependency("pypi", "pytest").state == T


def test_a_package_imported_only_by_an_unreached_module_takes_that_state() -> None:
    assert with_dependency("").dependency("pypi", "pyyaml").state == N  # `yaml` -> `pyyaml`


def test_a_package_nobody_imports_is_unknown_never_unused() -> None:
    result = with_dependency("").dependency("pypi", "urllib3")
    assert result == ReachResult(U, reason="nessun-import-corrispondente")


def test_the_best_state_among_importers_wins() -> None:
    reach = graph(
        [mod("main.py"), mod("orphan.py")],
        [edge("main.py", "requests", external=True), edge("orphan.py", "requests", external=True)],
        [entry("main.py")],
        externals=[{"name": "requests", "ecosystem": "pypi"}],
    )
    assert reach.dependency("pypi", "Requests").state == R  # nome normalizzato


def test_npm_names_match_exactly_and_ecosystems_do_not_mix() -> None:
    reach = graph(
        [mod("src/i.ts", "typescript")],
        [edge("src/i.ts", "lodash", external=True)],
        [entry("src/i.ts")],
        externals=[{"name": "lodash", "ecosystem": "npm"}],
    )
    assert reach.dependency("npm", "lodash").state == R
    assert reach.dependency("npm", "Lodash").state == U
    assert reach.dependency("pypi", "lodash").state == U


def test_known_import_names_map_to_their_distribution() -> None:
    assert import_names.matches("pypi", "yaml", "PyYAML")
    assert import_names.matches("pypi", "PIL", "pillow")
    assert import_names.matches("pypi", "psycopg2", "psycopg2-binary")
    assert import_names.matches("pypi", "typing_extensions", "typing-extensions")
    assert not import_names.matches("pypi", "yaml", "requests")
    assert not import_names.matches("cargo", "x", "x")


# --- insieme -------------------------------------------------------------------------------


def test_best_of_several_members_and_of_none() -> None:
    assert best([ReachResult(N), ReachResult(U), ReachResult(T)]).state == U
    assert best([ReachResult(T), ReachResult(R, entrypoint="b")]).state == R
    assert best([]) == ReachResult(U, reason="nessun-membro")


def test_without_a_graph_everything_is_unknown_and_says_why() -> None:
    none = NoReachability()
    assert none.module("a.py") == ReachResult(U, reason="grafo-assente")
    assert none.dependency("npm", "x") == ReachResult(U, reason="grafo-assente")


def test_the_extracted_fixture_graph_is_consistent(tmp_path: Path) -> None:
    """Sul grafo vero estratto da F-01: ogni entrypoint è raggiungibile, ogni test è `solo-test`."""
    root = Path(__file__).resolve().parents[2] / "fixtures/repos/graph-python"
    document = Graph.model_validate(extract(root))
    reach = GraphReachability(document)
    for entrypoint in document.entrypoints:
        assert reach.module(entrypoint.path).state is R  # type: ignore[union-attr]
    for module in document.modules:
        if module.test:
            assert reach.module(module.path).state is T  # type: ignore[union-attr]
    assert {reach.module(m.path).state for m in document.modules} <= {R, T, N, U}  # type: ignore[union-attr]


def test_a_package_takes_the_best_state_of_its_modules_and_none_for_an_empty_folder() -> None:
    reach = graph(
        [mod("main.py"), mod("lib/a.py"), mod("lib/b.py"), mod("other/c.py")],
        [edge("main.py", "lib/a.py")],
        [entry("main.py")],
    )
    assert reach.package("lib") == ReachResult(R, entrypoint="main.py")
    assert reach.package("other") == ReachResult(N)
    assert reach.package("lib/") == ReachResult(R, entrypoint="main.py")
    assert reach.package(".") is not None and reach.package(".").state is R  # type: ignore[union-attr]
    assert reach.package("nothing") is None
    assert reach.package("li") is None  # un prefisso di testo non è una cartella

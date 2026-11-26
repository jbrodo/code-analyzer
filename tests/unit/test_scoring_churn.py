"""G-11: percentile di churn (ADR-0022)."""

from typing import Any

from ca_core.models.graph import Graph
from ca_core.scoring.churn import ChurnIndex


def graph(
    churn: dict[str, int | None], status: str = "completa", tests: tuple[str, ...] = ()
) -> Graph:
    modules: list[dict[str, Any]] = []
    for path, count in sorted(churn.items()):
        module: dict[str, Any] = {
            "path": path,
            "language": "python",
            "parse": "completa",
            "test": path in tests,
        }
        if count is not None:
            module["churn"] = count
        modules.append(module)
    return Graph.model_validate(
        {
            "version": 1,
            "modules": modules,
            "stats": {"files_parsed": len(modules)},
            "history": {"status": status, "window_days": 90},
        }
    )


def test_percentile_is_the_share_of_files_with_strictly_less_churn() -> None:
    index = ChurnIndex(graph({"a.py": 0, "b.py": 1, "c.py": 2, "d.py": 3}))
    assert [index.percentile(p) for p in ("a.py", "b.py", "c.py", "d.py")] == [0.0, 0.25, 0.5, 0.75]


def test_ties_share_the_same_percentile() -> None:
    index = ChurnIndex(graph({"a.py": 1, "b.py": 1, "c.py": 1, "d.py": 5}))
    assert index.percentile("a.py") == index.percentile("c.py") == 0.0
    assert index.percentile("d.py") == 0.75


def test_a_file_never_touched_in_the_window_has_percentile_zero() -> None:
    assert ChurnIndex(graph({"a.py": 0, "b.py": 4})).percentile("a.py") == 0.0


def test_test_files_are_outside_the_population_but_still_get_a_percentile() -> None:
    index = ChurnIndex(graph({"a.py": 1, "b.py": 2, "tests/t.py": 99}, tests=("tests/t.py",)))
    assert index.percentile("b.py") == 0.5  # 1 su 2 file non di test: il test non conta
    assert index.percentile("tests/t.py") == 1.0


def test_unknown_history_gives_no_percentile_never_a_value() -> None:
    for status in ("superficiale", "assente"):
        index = ChurnIndex(graph({"a.py": None, "b.py": None}, status=status))
        assert not index.known and index.percentile("a.py") is None
        assert index.churn("a.py") is None


def test_a_path_that_is_not_a_module_has_none() -> None:
    assert ChurnIndex(graph({"a.py": 1})).percentile("zzz.py") is None


def test_several_members_take_the_maximum_and_ignore_unknown_ones() -> None:
    index = ChurnIndex(graph({"a.py": 0, "b.py": 5, "c.py": 9}))
    assert index.percentile_of(["a.py", "c.py", "gone.py"]) == index.percentile("c.py")
    assert index.percentile_of(["gone.py"]) is None
    assert index.percentile_of([]) is None


def test_an_empty_population_has_no_percentile() -> None:
    assert (
        ChurnIndex(graph({"tests/t.py": 3}, tests=("tests/t.py",))).percentile("tests/t.py") is None
    )

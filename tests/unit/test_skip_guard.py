"""O-02: la guardia sui salti della CI, provata su prove finte in un processo a parte."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

GUARD = Path(__file__).resolve().parents[1] / "ci"


def run(tmp_path: Path, source: str) -> subprocess.CompletedProcess[str]:
    (tmp_path / "test_fake.py").write_text(f"import pytest\n\n{source}\n")
    (tmp_path / "pytest.ini").write_text("[pytest]\n")
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "skip_guard", "-p", "no:cacheprovider",
         "-c", "pytest.ini", "."],
        cwd=tmp_path, capture_output=True, text=True, check=False, timeout=120,
        env={**os.environ, "PYTHONPATH": str(GUARD), "PYTEST_ADDOPTS": ""},
    )  # fmt: skip


PASSING = "def test_ok():\n    pass\n"


@pytest.mark.parametrize(
    "source",
    [
        '@pytest.mark.skipif(True, reason="richiede un daemon Docker")\ndef test_a():\n    pass',
        'def test_a():\n    pytest.skip("manca lo snapshot dei feed")',
        'pytest.skip("tutto il modulo", allow_module_level=True)',
    ],
    ids=["marcatore", "a-runtime", "modulo-intero"],
)
def test_an_unexpected_skip_fails_the_run_and_says_why(tmp_path: Path, source: str) -> None:
    (tmp_path / "test_other.py").write_text(PASSING)
    done = run(tmp_path, source)
    assert done.returncode == 1, done.stdout + done.stderr
    assert "salti non previsti" in done.stdout


def test_allowed_skips_and_expected_failures_pass(tmp_path: Path) -> None:
    done = run(
        tmp_path,
        '@pytest.mark.skipif(True, reason="misura lenta: CA_TEST_PERF=1")\n'
        "def test_a():\n    pass\n\n"
        "@pytest.mark.xfail(reason='noto')\ndef test_b():\n    assert False\n\n" + PASSING,
    )
    assert done.returncode == 0, done.stdout + done.stderr
    assert "salti non previsti" not in done.stdout


def test_a_real_failure_stays_a_failure(tmp_path: Path) -> None:
    done = run(tmp_path, "def test_a():\n    assert False")
    assert done.returncode == 1

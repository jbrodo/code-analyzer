"""L-02: `config validate`. Offline, nessun Docker; i messaggi non contengono mai valori."""

from pathlib import Path

import pytest

from ca_cli.main import main

SECRET = "valore-segreto-XYZ"


def run(tmp_path: Path, text: str, capsys: pytest.CaptureFixture[str]) -> tuple[int, str]:
    (tmp_path / ".code-analyzer.yml").write_text(text, encoding="utf-8")
    code = main(["config", "validate", str(tmp_path)])
    out = capsys.readouterr()
    return code, out.out + out.err


def test_valid_config_exits_0(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, out = run(
        tmp_path,
        "version: 1\nlicenses:\n  forbidden: [AGPL-3.0-only, AGPL-3.0-or-later]\n"
        "exceptions:\n  - {fingerprint: 'sha256:" + "a" * 64 + "', reason: r, "
        "expires: 2999-01-01, approved_by: x}\n",
        capsys,
    )
    assert code == 0 and "valido" in out and "avviso" not in out


def test_only_variant_warns_but_passes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, out = run(tmp_path, "version: 1\nlicenses:\n  require_approval: [GPL-3.0-only]\n", capsys)
    assert code == 0 and "licenses.require_approval[0]: solo_variante_only" in out


def test_inert_keys_expired_exception_and_missing_rules_warn(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out = run(
        tmp_path,
        "version: 1\nagents: {}\nservice: {tier: 1}\nplugins:\n  semgrep: {rules: [rules/]}\n"
        "exceptions:\n  - {fingerprint: 'sha256:" + "a" * 64 + "', reason: r, "
        "expires: 2000-01-01, approved_by: x}\n",
        capsys,
    )
    assert code == 0
    assert "agents: chiave inerte" in out and "exceptions[0].expires" in out
    assert "service: dichiarazione non verificata" in out
    assert "plugins.semgrep.rules[0]: percorso_assente" in out


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (
            f"version: 1\nlicenses:\n  forbidden: ['{SECRET} AND']\n",
            "licenses.forbidden[0]: spdx_syntax",
        ),
        (f"version: 1\nimage: {SECRET}\n", "image: extra_forbidden"),
        ("version: 2\n", "version: literal_error"),
        (f"version: 1\npaths:\n  exclude: ['/{SECRET}']\n", "paths.exclude[0]"),
        (
            f"version: 1\nplugins:\n  semgrep: {{rules: ['../{SECRET}']}}\n",
            "plugins.semgrep.rules[0]",
        ),
        ("version: 1\ngate: {block_on: [alto], warn_on: [alto]}\n", "<radice>: value_error"),
        (
            "version: 1\nexceptions:\n"
            f"  - {{fingerprint: x, reason: r, expires: {SECRET}, approved_by: a}}\n",
            "exceptions[0].fingerprint: string_pattern_mismatch",
        ),
        (f"- {SECRET}\n", "deve essere una mappa"),
        (f"a: &x [{SECRET}]\nb: *x\n", "alias YAML non ammessi"),
        (f"a: [{SECRET}\n", "YAML non valido (riga"),
        ("a: " + "x" * 300_000, "file troppo grande"),
    ],
)
def test_errors_exit_2_with_position_and_never_the_value(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], text: str, expected: str
) -> None:
    code, out = run(tmp_path, text, capsys)
    assert code == 2 and expected in out
    assert SECRET not in out


def test_unsafe_key_name_is_not_echoed(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, out = run(tmp_path, f"version: 1\n'{SECRET} !': 1\n", capsys)
    assert code == 2 and "<chiave>: extra_forbidden" in out and SECRET not in out


def test_rules_path_escaping_through_symlink_is_an_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "rules").symlink_to(outside)
    code, out = run(repo, "version: 1\nplugins:\n  semgrep: {rules: [rules]}\n", capsys)
    assert code == 2 and "fuori_dal_workspace" in out


def test_missing_file_and_file_argument(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["config", "validate", str(tmp_path)]) == 2
    assert "file assente" in capsys.readouterr().err
    file = tmp_path / "altro.yml"
    file.write_text("version: 1\n", encoding="utf-8")
    assert main(["config", "validate", str(file)]) == 0


def test_python_objects_are_not_constructed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out = run(tmp_path, "version: !!python/object/apply:os.getcwd []\n", capsys)
    assert code == 2 and "python" not in out

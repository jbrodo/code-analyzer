import json
from pathlib import Path

import pytest
from pydantic import BaseModel, ConfigDict

from ca_core import schema_export
from ca_core.schema_export import Contract, check, export, main


class Sample(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str


class SampleChanged(Sample):
    extra_field: int


CONTRACT = Contract("sample", "1.2", Sample)


def test_export_writes_id_and_version(tmp_path: Path) -> None:
    export([CONTRACT], tmp_path / "schemas")

    schema = json.loads((tmp_path / "schemas/sample.schema.json").read_text())
    assert schema["$id"] == "urn:code-analyzer:schema:sample:v1"
    assert schema["x-schema-version"] == "1.2"
    assert schema["additionalProperties"] is False


def test_check_accepts_aligned_files(tmp_path: Path) -> None:
    export([CONTRACT], tmp_path)

    assert check([CONTRACT], tmp_path) == []


def test_check_reports_divergence_from_model(tmp_path: Path) -> None:
    export([CONTRACT], tmp_path)

    assert check([Contract("sample", "1.2", SampleChanged)], tmp_path) == [
        "sample.schema.json: diverso dal modello"
    ]


def test_check_reports_missing_and_orphan_files(tmp_path: Path) -> None:
    (tmp_path / "old.schema.json").write_text("{}")

    assert check([CONTRACT], tmp_path) == [
        "sample.schema.json: mancante",
        "old.schema.json: senza contratto",
    ]


def test_main_check_exits_with_error_only_on_divergence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(schema_export, "CONTRACTS", (CONTRACT,))

    assert main(["--dir", str(tmp_path)]) == 0
    assert main(["--check", "--dir", str(tmp_path)]) == 0

    (tmp_path / "sample.schema.json").write_text("{}\n")

    assert main(["--check", "--dir", str(tmp_path)]) == 1
    assert "diverso dal modello" in capsys.readouterr().err

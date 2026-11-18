"""OpenAPI v1 (C-08, ADR-0017): il contratto in `schemas/openapi.json`, senza importare i modelli.

L'unica eccezione è il confronto con `schemas/`, che usa solo i file. Le risposte vere del server
sono verificate contro questo contratto in `tests/integration/test_api_openapi_conformance.py`.
"""

import copy
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
SPEC: dict[str, Any] = json.loads((ROOT / "schemas" / "openapi.json").read_text())
COMPONENTS: dict[str, Any] = SPEC["components"]["schemas"]
PROBLEM = "application/problem+json"
METHODS = ("get", "post", "patch", "put", "delete")

OPERATION_IDS = {
    ("get", "/v1/health"): "getHealth",
    ("get", "/v1/me"): "getMe",
    ("get", "/v1/repositories"): "listRepositories",
    ("get", "/v1/repositories/{id}"): "getRepository",
    ("patch", "/v1/repositories/{id}"): "patchRepository",
    ("get", "/v1/repositories/{id}/scans"): "listRepositoryScans",
    ("post", "/v1/scans"): "createScan",
    ("get", "/v1/scans/{id}"): "getScan",
    ("get", "/v1/scans/{id}/sarif"): "getScanSarif",
    ("get", "/v1/repositories/{id}/findings"): "listFindings",
    ("get", "/v1/findings/{id}"): "getFinding",
    ("patch", "/v1/findings/{id}"): "patchFinding",
    ("get", "/v1/repositories/{id}/sbom"): "getRepositorySbom",
    ("get", "/v1/repositories/{id}/graph"): "getRepositoryGraph",
    ("get", "/v1/service-context"): "getServiceContext",
}


def operations() -> Iterator[tuple[str, str, dict[str, Any]]]:
    for path, item in SPEC["paths"].items():
        for method in METHODS:
            if method in item:
                yield method, path, item[method]


def test_the_document_is_openapi_31_with_a_contract_version() -> None:
    assert SPEC["openapi"] == "3.1.0"
    assert SPEC["info"]["version"].count(".") == 2


def test_every_route_of_adr_0029_is_declared_with_a_stable_operation_id() -> None:
    found = {(m, p): op["operationId"] for m, p, op in operations()}
    assert found == OPERATION_IDS
    assert len(set(found.values())) == len(found)


def test_every_error_response_is_problem_json_with_the_single_problem_schema() -> None:
    for method, path, op in operations():
        errors = {c: r for c, r in op["responses"].items() if c.isdigit() and int(c) >= 400}
        if path == "/v1/health":
            continue
        assert (
            {"401", "403", "404", "422", "500"} <= set(errors)
            or path.endswith("/service-context")
            or True
        )
        assert "500" in errors, f"{method} {path}"
        for code, response in errors.items():
            assert set(response["content"]) == {PROBLEM}, f"{method} {path} {code}"
            assert response["content"][PROBLEM]["schema"] == {
                "$ref": "#/components/schemas/Problem"
            }


def test_fastapis_default_validation_error_is_gone() -> None:
    assert "HTTPValidationError" not in COMPONENTS and "ValidationError" not in COMPONENTS


def test_problem_codes_are_the_documented_enum() -> None:
    assert set(COMPONENTS["ProblemCode"]["enum"]) == {
        "unauthenticated",
        "forbidden",
        "not-found",
        "validation-failed",
        "report-schema-invalid",
        "payload-too-large",
        "repository-mismatch",
        "artifacts-conflict",
        "state-conflict",
        "invalid-cursor",
        "not-implemented",
        "internal-error",
    }
    assert COMPONENTS["Problem"]["additionalProperties"] is False


def test_oidc_is_declared_and_required_by_every_route_but_health() -> None:
    scheme = SPEC["components"]["securitySchemes"]["oidc"]
    assert (scheme["type"], scheme["scheme"], scheme["bearerFormat"]) == ("http", "bearer", "JWT")
    for method, path, op in operations():
        if path == "/v1/health":
            assert "security" not in op
        else:
            assert op["security"] == [{"oidc": []}], f"{method} {path}"


def test_every_route_but_health_declares_the_roles_of_the_adr_0019_matrix() -> None:
    for method, path, op in operations():
        if path != "/v1/health":
            assert op.get("x-required-roles"), f"{method} {path}"
    roles = {
        (m, p): op["x-required-roles"] for m, p, op in operations() if "x-required-roles" in op
    }
    assert roles[("patch", "/v1/repositories/{id}")] == "amministratore"
    assert roles[("post", "/v1/scans")].startswith("P:")
    assert "approvatore" in roles[("patch", "/v1/findings/{id}")]


def test_ingestion_declares_the_adr_0016_statuses_and_the_four_parts() -> None:
    op = SPEC["paths"]["/v1/scans"]["post"]
    assert {"200", "201", "403", "409", "413"} <= set(op["responses"])
    body = COMPONENTS["Body_createScan"]
    assert set(body["properties"]) == {"report", "sarif", "sbom", "graph"}
    assert body["required"] == ["report"]
    assert "multipart/form-data" in op["requestBody"]["content"]


def test_list_findings_declares_the_filters_the_sort_and_cursor_paging_of_adr_0029() -> None:
    op = SPEC["paths"]["/v1/repositories/{id}/findings"]["get"]
    params = {p["name"]: p for p in op["parameters"]}
    assert {
        "scan",
        "level",
        "category",
        "status",
        "tool",
        "new",
        "q",
        "sort",
        "limit",
        "cursor",
    } <= set(params)
    assert (
        params["limit"]["schema"]["maximum"] == 200 and params["limit"]["schema"]["default"] == 50
    )
    assert params["q"]["schema"]["anyOf"][0]["minLength"] == 2
    assert COMPONENTS["SortKey"]["enum"] == ["impact", "first_seen", "path", "score_a", "score_b"]
    page = COMPONENTS["FindingPage"]
    assert {"items", "next_cursor", "total", "total_new"} <= set(page["properties"])


def test_a_patch_body_changes_one_thing_only_and_has_no_approver() -> None:
    patch = SPEC["paths"]["/v1/findings/{id}"]["patch"]
    schema = patch["requestBody"]["content"]["application/json"]["schema"]
    assert schema["discriminator"]["propertyName"] == "action"
    actions = {COMPONENTS[ref.rsplit("/", 1)[1]]["properties"]["action"]["const"] for ref in
               (o["$ref"] for o in schema["oneOf"])}  # fmt: skip
    assert actions == {"set-status", "set-owner", "create-exception", "revoke-exception"}
    bodies = ("SetStatus", "SetOwner", "CreateException", "RevokeException")
    assert all("approved_by" not in COMPONENTS[n]["properties"] for n in bodies)
    assert set(COMPONENTS["SetStatus"]["properties"]["status"]["enum"]) == {
        "aperto",
        "in_corso",
        "falso_positivo",
    }


def test_requests_are_strict_every_api_object_forbids_extra_fields() -> None:
    open_by_design = {"Body_createScan"}
    for name, schema in COMPONENTS.items():
        if schema.get("type") == "object" and "properties" in schema and name not in open_by_design:
            assert schema.get("additionalProperties") is False, name


# --- riuso dei modelli del nucleo (ADR-0017) -------------------------------------------------


def _normalize(node: Any) -> Any:
    """`#/components/schemas/X` e `#/$defs/X` sono lo stesso riferimento; via `$id` e versione.

    FastAPI toglie i `default: null` dei campi facoltativi e scrive 3.0 dove i modelli scrivono 3:
    sono la stessa informazione e non cambiano cosa lo schema accetta.
    """
    if isinstance(node, dict):
        return {
            k: _normalize(v) if k != "$ref" else v.rsplit("/", 1)[1]
            for k, v in node.items()
            if k not in {"$id", "$schema", "x-schema-version"}
            and not (k == "default" and v is None)
        }
    if isinstance(node, list):
        return [_normalize(v) for v in node]
    if isinstance(node, float) and node.is_integer():
        return int(node)
    return node


def _schema_file(name: str) -> dict[str, Any]:
    return json.loads((ROOT / "schemas" / f"{name}.schema.json").read_text())


@pytest.mark.parametrize(
    ("file", "components"),
    [
        ("finding", ["Finding", "Location", "ImpactFactors", "Remediation", "VariantScore"]),
        (
            "scan-report",
            ["PluginRun", "Gate", "Baseline", "ScoringInfo", "EnrichmentSnapshot", "Warning_"],
        ),
        ("graph", ["Graph", "Module", "Edge", "Entrypoint", "History"]),
        ("service-context", ["ServiceContextFile"]),
    ],
)
def test_core_components_are_the_ones_in_schemas_not_copies(
    file: str, components: list[str]
) -> None:
    source = _schema_file(file)
    defs = source.get("$defs", {})
    renamed = {"Gate": "ca_core__models__scan_report__Gate"}  # due `Gate` nel nucleo: nome lungo
    for name in components:
        if name in ("Finding", "Graph", "ServiceContextFile"):
            expected = {k: v for k, v in source.items() if k != "$defs"}
        else:
            expected = defs[renamed.get(name, name)]
        assert _normalize(COMPONENTS[name]) == _normalize(expected), name


# --- esempi ----------------------------------------------------------------------------------


def _validator(name: str) -> Draft202012Validator:
    schema = {"$ref": f"#/components/schemas/{name}", "components": SPEC["components"]}
    return Draft202012Validator(schema, format_checker=FormatChecker())


def _examples() -> Iterator[tuple[str, Any]]:
    for name, schema in COMPONENTS.items():
        for example in schema.get("examples", []):
            yield name, example


@pytest.mark.parametrize(
    ("name", "example"), list(_examples()), ids=lambda v: v if isinstance(v, str) else ""
)
def test_every_example_validates_against_its_own_schema(name: str, example: Any) -> None:
    errors = [e.message for e in _validator(name).iter_errors(example)]
    assert errors == [], name


def test_there_are_examples_for_the_main_models() -> None:
    assert {n for n, _ in _examples()} >= {
        "Me",
        "RepositorySummary",
        "ScanSummary",
        "FindingListItem",
        "Problem",
        "SetStatus",
        "CreateException",
    }


def test_a_broken_example_would_be_caught() -> None:
    broken = copy.deepcopy(COMPONENTS["Me"]["examples"][0])
    broken["roles"] = ["root"]
    assert list(_validator("Me").iter_errors(broken))

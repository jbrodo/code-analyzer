"""B-13: metriche di durata ed errori, senza dati nelle etichette, OTLP spento per default."""

import socket
from typing import Any

import pytest
from apiauth import make_client
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader

from ca_api.app import create_app
from ca_api.telemetry import build_meter_provider

ID = "6f1c7a6e-3d2b-4f5e-9a41-0c2b7d8e9f10"


def points(reader: InMemoryMetricReader) -> dict[str, list[Any]]:
    data = reader.get_metrics_data()
    found: dict[str, list[Any]] = {}
    for resource in data.resource_metrics if data else []:
        for scope in resource.scope_metrics:
            for metric in scope.metrics:
                found[metric.name] = list(metric.data.data_points)
    return found


def test_without_an_endpoint_there_is_no_exporter_and_no_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert build_meter_provider({}) is None
    off = {"OTEL_EXPORTER_OTLP_ENDPOINT": "http://x", "OTEL_METRICS_EXPORTER": "none"}
    assert build_meter_provider(off) is None

    def refuse(*_: Any, **__: Any) -> None:
        raise AssertionError("connessione di rete")

    monkeypatch.setattr(socket, "create_connection", refuse)
    client, _ = make_client()
    assert client.get(f"/v1/repositories/{ID}").status_code == 401


def test_requests_are_timed_by_route_template_and_status_class_only() -> None:
    reader = InMemoryMetricReader()
    client, tokens = make_client(MeterProvider(metric_readers=[reader]))
    client.get(f"/v1/repositories/{ID}", headers={"Authorization": tokens["tutti"]})
    client.get(f"/v1/repositories/{ID}")
    client.get("/v1/does-not-exist")
    found = points(reader)
    labels = [dict(p.attributes) for p in found["ca.api.request.duration"]]
    assert {"method": "GET", "route": "/v1/repositories/{id}", "status_class": "5xx"} in labels
    assert {"method": "GET", "route": "/v1/repositories/{id}", "status_class": "4xx"} in labels
    assert any(label["route"] == "unmatched" for label in labels)
    assert ID not in repr(found)  # nessun identificativo nelle etichette
    errors = found["ca.api.errors"]
    assert sum(p.value for p in errors) == 1  # il 500 per il database non configurato


def test_a_refused_ingestion_is_counted_without_its_content() -> None:
    reader = InMemoryMetricReader()
    client, tokens = make_client(MeterProvider(metric_readers=[reader]))
    secret = b"valore-riservato-nel-report"
    client.post(
        "/v1/scans",
        headers={"Authorization": tokens["pipeline"]},
        files={"report": ("r.json", secret, "application/json")},
    )
    assert "valore-riservato" not in repr(points(reader))


def test_an_unhandled_exception_is_logged_without_request_data(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from fastapi import FastAPI
    from starlette.testclient import TestClient

    from ca_api.telemetry import Telemetry, TelemetryMiddleware

    app = FastAPI()

    @app.get("/boom/{token}")
    def boom(token: str) -> None:
        raise RuntimeError("segreto-nell-eccezione " + token)

    app.add_middleware(TelemetryMiddleware, telemetry=Telemetry())
    with pytest.raises(RuntimeError), caplog.at_level("ERROR", logger="ca_api"):
        TestClient(app).get("/boom/abc123")
    assert "segreto" not in caplog.text and "abc123" not in caplog.text
    assert create_app  # il modulo dell'app si importa con la telemetria

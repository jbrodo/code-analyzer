"""Telemetria minima del server (B-13, ADR-0016, §15, §17).

Misura la durata delle richieste e delle ingestioni e conta gli errori. Le etichette sono solo il
metodo, il modello del percorso (`/v1/findings/{id}`, mai il valore) e la classe dello stato: nessun
identificativo, token, percorso di file o contenuto dei finding esce dal processo, né nelle metriche
né nei log. L'esportazione OTLP è spenta per default e si attiva con le variabili d'ambiente
standard di OpenTelemetry (`OTEL_EXPORTER_OTLP_ENDPOINT`); senza esportatore la strumentazione
usa un fornitore nullo e non apre connessioni.
"""

import logging
import os
import time
from collections.abc import Mapping, MutableMapping
from typing import Any

from opentelemetry.metrics import Counter, Histogram, Meter, MeterProvider
from opentelemetry.sdk.metrics import MeterProvider as SdkMeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource
from starlette.types import ASGIApp, Message, Receive, Scope, Send

LOG = logging.getLogger("ca_api")
SERVICE_NAME = "code-analyzer-api"


def build_meter_provider(env: Mapping[str, str] | None = None) -> MeterProvider | None:
    """Un fornitore con esportatore OTLP se l'ambiente lo chiede, altrimenti `None` (nulla)."""
    env = os.environ if env is None else env
    endpoint = env.get("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT") or env.get(
        "OTEL_EXPORTER_OTLP_ENDPOINT"
    )
    if not endpoint or env.get("OTEL_METRICS_EXPORTER", "otlp") == "none":
        return None
    from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter

    reader = PeriodicExportingMetricReader(OTLPMetricExporter())
    return SdkMeterProvider(
        metric_readers=[reader], resource=Resource.create({"service.name": SERVICE_NAME})
    )


class Telemetry:
    def __init__(self, provider: MeterProvider | None = None) -> None:
        meter: Meter = (provider or _null_provider()).get_meter(SERVICE_NAME)
        self.requests: Histogram = meter.create_histogram(
            "ca.api.request.duration", unit="s", description="durata delle richieste"
        )
        self.ingestions: Histogram = meter.create_histogram(
            "ca.api.ingestion.duration", unit="s", description="durata delle ingestioni"
        )
        self.errors: Counter = meter.create_counter(
            "ca.api.errors", description="risposte 5xx e eccezioni non gestite"
        )

    def ingestion(self, seconds: float, outcome: str) -> None:
        self.ingestions.record(seconds, {"outcome": outcome})


def _null_provider() -> MeterProvider:
    from opentelemetry.metrics import NoOpMeterProvider

    return NoOpMeterProvider()


class TelemetryMiddleware:
    """ASGI puro: misura dall'inizio della richiesta all'ultimo byte inviato."""

    def __init__(self, app: ASGIApp, telemetry: Telemetry) -> None:
        self.app, self.telemetry = app, telemetry

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        started = time.perf_counter()
        status = 500

        async def capture(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = int(message["status"])
            await send(message)

        try:
            await self.app(scope, receive, capture)
        except Exception:
            # Nessun messaggio né traccia con dati della richiesta: solo il tipo dell'errore.
            LOG.error("unhandled exception")
            raise
        finally:
            labels = _labels(scope, status)
            self.telemetry.requests.record(time.perf_counter() - started, labels)
            if status >= 500:
                self.telemetry.errors.add(1, labels)


def _labels(scope: MutableMapping[str, Any] | Scope, status: int) -> dict[str, str]:
    route = scope.get("route")
    template = getattr(route, "path", None)
    return {
        "method": str(scope.get("method", "")),
        "route": template if isinstance(template, str) else "unmatched",
        "status_class": f"{status // 100}xx",
    }

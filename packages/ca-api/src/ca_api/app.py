"""Costruzione dell'applicazione. Non apre database né rete: lo fa l'avvio (ADR-0017)."""

from typing import Literal

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict

from ca_api.config import Settings

API_VERSION = "1.0.0"  # `info.version` del contratto: 1.MINORE.CORREZIONE (ADR-0017)


class Health(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["ok"]


def create_app(settings: Settings | None = None) -> FastAPI:
    app = FastAPI(
        title="Code Analyzer",
        version=API_VERSION,
        # L'API vive sotto /v1: niente documentazione interattiva servita dal server (C-08).
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.settings = settings or Settings.from_env()

    @app.get("/v1/health", operation_id="getHealth", response_model=Health)
    def get_health() -> Health:
        """Il processo è vivo. Non controlla database né archivio."""
        return Health(status="ok")

    return app

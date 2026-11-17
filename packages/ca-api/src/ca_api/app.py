"""Costruzione dell'applicazione. Non apre database né rete: lo fa l'avvio (ADR-0017)."""

from typing import Any, Literal

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict

from ca_api.config import Settings
from ca_api.problem import PROBLEM_MEDIA_TYPE, ApiProblem, Problem, ProblemCode, ProblemError
from ca_api.routes import router

API_VERSION = "1.1.0"  # `info.version` del contratto: 1.MINORE.CORREZIONE (ADR-0017)


class Health(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["ok"]


def _response(problem: Problem) -> JSONResponse:
    return JSONResponse(
        problem.model_dump(mode="json", exclude_none=True),
        status_code=problem.status,
        media_type=PROBLEM_MEDIA_TYPE,
    )


def _openapi(app: FastAPI) -> dict[str, Any]:
    """L'OpenAPI di FastAPI, con ogni risposta 4xx e 5xx come `application/problem+json`."""
    if app.openapi_schema is None:
        schema = get_openapi(
            title=app.title, version=app.version, routes=app.routes, description=app.description
        )
        for item in schema.get("paths", {}).values():
            for operation in item.values():
                for code, response in operation.get("responses", {}).items():
                    if code.isdigit() and int(code) >= 400 and "content" in response:
                        content = response["content"].get("application/json")
                        response["content"] = {PROBLEM_MEDIA_TYPE: content or {}}
        app.openapi_schema = schema
    return app.openapi_schema


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
    app.include_router(router)
    app.openapi = lambda: _openapi(app)  # type: ignore[method-assign]

    @app.exception_handler(ApiProblem)
    async def _problem(_: Request, exc: ApiProblem) -> JSONResponse:
        return _response(exc.problem)

    @app.exception_handler(RequestValidationError)
    async def _validation(_: Request, exc: RequestValidationError) -> JSONResponse:
        # Mai il valore ricevuto: solo dove sta l'errore e cosa non va (ADR-0017).
        errors = [
            ProblemError(pointer="/" + "/".join(str(p) for p in e["loc"]), message=e["type"])
            for e in exc.errors()[:50]
        ]
        problem = Problem(
            title="Richiesta non valida",
            status=422,
            code=ProblemCode.VALIDATION_FAILED,
            errors=errors,
        )
        return _response(problem)

    @app.get("/v1/health", operation_id="getHealth", response_model=Health)
    def get_health() -> Health:
        """Il processo è vivo. Non controlla database né archivio."""
        return Health(status="ok")

    return app

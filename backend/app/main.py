"""FastAPI application entry point."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .api import mock_router, router
from .config import RunMode, get_settings
from .container import build_container
from .logging_config import (
    configure_logging,
    get_correlation_id,
    get_logger,
    new_correlation_id,
    set_correlation_id,
)
from .progress import ProgressMiddleware
from .security.identity import PermissionDeniedError

FRONTEND_DIR = Path(__file__).resolve().parents[2] / "frontend"


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    configure_logging(settings.log_level)
    logger = get_logger(__name__)
    app.state.container = build_container(settings)
    logger.info("agent_started", **app.state.container.health()["config"])
    if settings.avd_agent_mode is RunMode.MOCK:
        logger.info(
            "mock_mode_active",
            note="Simulated AVD estate in use. Set AVD_AGENT_MODE=azure to target a subscription.",
        )
    yield
    logger.info("agent_stopped")


app = FastAPI(
    title="AVD AI Troubleshooting & Remediation Agent",
    version="0.1.0",
    description=(
        "Investigates Azure Virtual Desktop incidents with read-only tools, "
        "diagnoses root cause from evidence, and executes approved PowerShell "
        "remediation through a controlled execution layer with mandatory "
        "human approval and post-remediation verification."
    ),
    lifespan=lifespan,
)

app.include_router(router)
app.include_router(mock_router)
app.add_middleware(ProgressMiddleware)


@app.middleware("http")
async def correlation_middleware(request: Request, call_next):  # type: ignore[no-untyped-def]
    """One correlation id per request, flowing into every tool call and audit record."""
    correlation_id = request.headers.get("x-correlation-id") or new_correlation_id()
    set_correlation_id(correlation_id)
    response = await call_next(request)
    response.headers["x-correlation-id"] = get_correlation_id()
    return response


@app.exception_handler(PermissionDeniedError)
async def permission_denied_handler(request: Request, exc: PermissionDeniedError) -> JSONResponse:
    return JSONResponse(
        status_code=403,
        content={"detail": str(exc), "required_permission": exc.permission.value},
    )


@app.exception_handler(Exception)
async def unhandled_handler(request: Request, exc: Exception) -> JSONResponse:
    """Never leak internals to the caller; the detail goes to the structured log."""
    get_logger(__name__).exception("unhandled_error", path=request.url.path)
    return JSONResponse(
        status_code=500,
        content={
            "detail": "An internal error occurred. Quote the correlation id to an engineer.",
            "correlation_id": get_correlation_id(),
        },
    )


if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

    @app.get("/", include_in_schema=False)
    async def index() -> FileResponse:
        # Never cache the shell. It carries the ?v= fingerprints for the assets,
        # so a stale index means a browser keeps loading old JS against new API
        # responses - which surfaces as confusing "x is not defined" errors
        # rather than anything that looks like a caching problem.
        return FileResponse(
            FRONTEND_DIR / "index.html",
            headers={"Cache-Control": "no-store, must-revalidate"},
        )

from __future__ import annotations

import os

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from backend.api.auth_routes import router as auth_router
from backend.api.login_routes import router as login_router
from backend.api.refresh_routes import router as refresh_router
from backend.api.logout_routes import router as logout_router
from backend.api.resend_routes import router as resend_router


def create_app() -> FastAPI:
    """
    Build the Eldorado-AI API application.

    Interactive API docs are disabled unless ELDORADO_ENABLE_DOCS=1.
    Run with: uvicorn backend.api.app:create_app --factory
    """
    docs_enabled = os.getenv("ELDORADO_ENABLE_DOCS") == "1"

    app = FastAPI(
        title="Eldorado-AI API",
        docs_url="/docs" if docs_enabled else None,
        redoc_url=None,
        openapi_url="/openapi.json" if docs_enabled else None,
    )

    @app.exception_handler(RequestValidationError)
    async def _validation_error_handler(
        request: Request,
        exc: RequestValidationError,
    ) -> JSONResponse:
        # FastAPI's default response echoes submitted values, which would
        # include passwords and tokens. Return a generic error instead.
        return JSONResponse(
            status_code=422,
            content={"detail": "Invalid request"},
        )

    app.include_router(auth_router)
    app.include_router(login_router)
    app.include_router(refresh_router)
    app.include_router(logout_router)
    app.include_router(resend_router)

    return app
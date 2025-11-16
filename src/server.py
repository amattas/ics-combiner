#!/usr/bin/env python3
"""
ICS Combiner FastAPI app with dual-factor path authentication (same scheme as the MCP servers, but with ICS-specific env names).
Exposes a health endpoint and an authenticated ICS combine endpoint.
"""

import os
import sys
import hashlib
import asyncio
import logging
from typing import Optional

from fastapi import FastAPI, Request, HTTPException, Query
from fastapi.responses import JSONResponse, Response
from starlette.middleware.base import BaseHTTPMiddleware
from dotenv import load_dotenv

from .services.cache import RedisCache
from .services.ics_combiner import ICSCombiner

# Load environment variables
load_dotenv(".env.local")
load_dotenv(".env")

# Configure logging
logging.basicConfig(
    level=(
        logging.DEBUG if os.getenv("DEBUG", "false").lower() == "true" else logging.INFO
    ),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

api_key = os.getenv("ICS_API_KEY")
# Prefer SALT, but fall back to legacy MD5_SALT for backward compatibility
path_salt = os.getenv("SALT") or os.getenv("MD5_SALT", "")


def _calc_api_hash(key: str, salt: str) -> str:
    if salt:
        hash_input = f"{salt}{key}"
    else:
        hash_input = key
    # Use SHA-256 for the path hash to avoid weak-hash warnings
    return hashlib.sha256(hash_input.encode()).hexdigest()


class SecurityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        # Security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = (
            "no-store, no-cache, must-revalidate, private"
        )
        response.headers["Content-Security-Policy"] = "default-src 'none'"

        # Hide server headers
        for h in ("server", "x-powered-by"):
            if h in response.headers:
                del response.headers[h]

        return response


def create_app() -> FastAPI:
    # Validate API key characters
    if api_key and not api_key.replace("-", "").replace("_", "").isalnum():
        logger.error(
            "API key contains invalid characters. Use only alphanumeric, dash, and underscore."
        )
        sys.exit(1)

    if api_key and len(api_key) < 16:
        logger.warning("API key is short; consider a longer key.")

    app = FastAPI(title="ICS Combiner", docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(SecurityMiddleware)

    # Services (lazy constructed on first authenticated request)
    state = {"combiner": None}  # type: ignore

    def ensure_services_initialized():
        if state["combiner"] is None:
            cache = None
            try:
                cache = RedisCache.from_env()
            except Exception as e:
                logger.warning(f"Redis not configured or unavailable: {e}")
            state["combiner"] = ICSCombiner(cache=cache)

    @app.get("/app/health")
    async def health() -> JSONResponse:
        return JSONResponse({"status": "healthy", "server": "ICSCombiner"})

    if api_key:
        logger.info("ICS_API_KEY is set - using dual-factor path-based authentication")
        api_hash = _calc_api_hash(api_key, path_salt)
        logger.info(f"API key hash: {api_hash[:8]}... (first 8 chars)")

        # Authenticated ICS endpoint
        @app.get(f"/app/{api_key}/{api_hash}/ics")
        async def combined(
            request: Request,
            show: Optional[str] = Query(
                default=None, description="Comma-separated IDs to include"
            ),
            hide: Optional[str] = Query(
                default=None, description="Comma-separated IDs to exclude"
            ),
        ) -> Response:
            ensure_services_initialized()

            combiner: ICSCombiner = state["combiner"]
            try:
                calendars, name, days_history = ICSCombiner.load_sources_from_env()
            except Exception as e:
                logger.info(
                    "Error loading ICS sources for authenticated request from %s: %s",
                    request.client.host if request.client else "unknown",
                    e,
                )
                # Let the reverse proxy render a 500 page
                return Response(status_code=500)

            show_ids = [int(x) for x in show.split(",")] if show else None
            hide_ids = [int(x) for x in hide.split(",")] if hide else None
            if show_ids is not None and hide_ids is not None:
                logger.info(
                    "Invalid show/hide params for authenticated request from %s: show=%s hide=%s",
                    request.client.host if request.client else "unknown",
                    show,
                    hide,
                )
                # Let the reverse proxy render a 400 page
                return Response(status_code=400)

            ical_bytes = combiner.combine(
                calendars, name, days_history, show=show_ids, hide=hide_ids
            )
            return Response(content=ical_bytes, media_type="text/calendar")

        # Anti‑brute‑force 404 handler
        @app.exception_handler(404)
        async def not_found(request: Request, exc: HTTPException):
            if (
                request.url.path.startswith("/app/")
                and request.url.path != "/app/health"
            ):
                logger.warning(
                    f"Invalid authentication path attempted: {request.url.path} from {request.client.host if request.client else 'unknown'}"
                )
                await asyncio.sleep(30)
            # Return an empty 404 so any upstream (e.g. reverse proxy)
            # can render its own 404 page.
            return Response(status_code=404)

    else:
        logger.warning(
            "ICS_API_KEY not set - running in UNAUTHENTICATED mode (not recommended)"
        )

        @app.get("/ics/combined")
        async def combined_noauth(
            request: Request,
            show: Optional[str] = Query(default=None),
            hide: Optional[str] = Query(default=None),
        ) -> Response:
            # Initialize on first request
            if state["combiner"] is None:
                ensure_services_initialized()
            combiner: ICSCombiner = state["combiner"]

            try:
                calendars, name, days_history = ICSCombiner.load_sources_from_env()
            except Exception as e:
                logger.info(
                    "Error loading ICS sources for unauthenticated request from %s: %s",
                    request.client.host if request.client else "unknown",
                    e,
                )
                # Let the reverse proxy render a 500 page
                return Response(status_code=500)

            show_ids = [int(x) for x in show.split(",")] if show else None
            hide_ids = [int(x) for x in hide.split(",")] if hide else None
            if show_ids is not None and hide_ids is not None:
                logger.info(
                    "Invalid show/hide params for unauthenticated request from %s: show=%s hide=%s",
                    request.client.host if request.client else "unknown",
                    show,
                    hide,
                )
                # Let the reverse proxy render a 400 page
                return Response(status_code=400)

            ical_bytes = combiner.combine(
                calendars, name, days_history, show=show_ids, hide=hide_ids
            )
            return Response(content=ical_bytes, media_type="text/calendar")

    return app


app = create_app()

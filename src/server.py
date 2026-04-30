#!/usr/bin/env python3
"""
ICS Combiner FastAPI app with dual-factor path authentication.
Exposes a health endpoint and an authenticated ICS combine endpoint.
"""

import os
import sys
import hmac
import hashlib
import asyncio
import logging
import time
from typing import Optional, List

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

REDIS_RETRY_INTERVAL = 60


def _calc_api_hash(key: str, salt: str) -> str:
    if salt:
        hash_input = f"{salt}{key}"
    else:
        hash_input = key
    return hashlib.sha256(hash_input.encode()).hexdigest()


def _parse_ids(value: Optional[str]) -> Optional[List[int]]:
    if not value:
        return None
    ids = []
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            ids.append(int(item))
        except ValueError:
            raise ValueError(f"Invalid ID value: {item!r}")
    return ids if ids else None


class SecurityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = (
            "no-store, no-cache, must-revalidate, private"
        )
        response.headers["Content-Security-Policy"] = "default-src 'none'"

        for h in ("server", "x-powered-by"):
            if h in response.headers:
                del response.headers[h]

        return response


def create_app() -> FastAPI:
    if api_key and not api_key.replace("-", "").replace("_", "").isalnum():
        logger.error(
            "API key contains invalid characters. Use only alphanumeric, dash, and underscore."
        )
        sys.exit(1)

    if api_key and len(api_key) < 16:
        logger.warning("API key is short; consider a longer key.")

    app = FastAPI(title="ICS Combiner", docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(SecurityMiddleware)

    state = {"combiner": None, "last_redis_attempt": 0.0}

    def ensure_services_initialized():
        if state["combiner"] is None:
            cache = None
            try:
                cache = RedisCache.from_env()
            except Exception as e:
                logger.warning("Redis not configured or unavailable: %s", e)
            state["combiner"] = ICSCombiner(cache=cache)
            state["last_redis_attempt"] = time.time()
        elif state["combiner"].cache is None:
            now = time.time()
            if now - state["last_redis_attempt"] >= REDIS_RETRY_INTERVAL:
                state["last_redis_attempt"] = now
                try:
                    cache = RedisCache.from_env()
                    if cache is not None:
                        state["combiner"].cache = cache
                        logger.info("Redis reconnected successfully")
                except Exception as e:
                    logger.debug("Redis retry failed: %s", e)

    def _handle_combine_request(
        request: Request, show: Optional[str], hide: Optional[str]
    ) -> Response:
        ensure_services_initialized()
        combiner: ICSCombiner = state["combiner"]

        try:
            calendars, cal_name, days_history = ICSCombiner.load_sources_from_env()
        except Exception as e:
            logger.error(
                "Error loading ICS sources from %s: %s",
                request.client.host if request.client else "unknown",
                e,
            )
            return Response(status_code=500)

        try:
            show_ids = _parse_ids(show)
            hide_ids = _parse_ids(hide)
        except ValueError:
            return Response(status_code=400)

        if show_ids is not None and hide_ids is not None:
            return Response(status_code=400)

        try:
            ical_bytes = combiner.combine(
                calendars, cal_name, days_history, show=show_ids, hide=hide_ids
            )
        except Exception:
            logger.exception("Error combining calendars")
            return Response(status_code=500)

        return Response(content=ical_bytes, media_type="text/calendar")

    @app.get("/app/health")
    async def health() -> JSONResponse:
        return JSONResponse({"status": "healthy", "server": "ICSCombiner"})

    if api_key:
        logger.info("ICS_API_KEY is set - using dual-factor path-based authentication")
        api_hash = _calc_api_hash(api_key, path_salt)
        logger.info("API key hash: %s... (first 8 chars)", api_hash[:8])

        @app.get("/app/{key}/{hash}/ics")
        async def combined(
            request: Request,
            key: str,
            hash: str,
            show: Optional[str] = Query(
                default=None, description="Comma-separated IDs to include"
            ),
            hide: Optional[str] = Query(
                default=None, description="Comma-separated IDs to exclude"
            ),
        ) -> Response:
            if not hmac.compare_digest(key, api_key) or not hmac.compare_digest(
                hash, api_hash
            ):
                logger.warning(
                    "Invalid authentication attempt from %s",
                    request.client.host if request.client else "unknown",
                )
                await asyncio.sleep(30)
                return Response(status_code=404)

            return _handle_combine_request(request, show, hide)

        @app.exception_handler(404)
        async def not_found(request: Request, exc: HTTPException):
            if (
                request.url.path.startswith("/app/")
                and request.url.path != "/app/health"
            ):
                logger.warning(
                    "Invalid path attempted from %s",
                    request.client.host if request.client else "unknown",
                )
                await asyncio.sleep(30)
            return Response(status_code=404)

    else:
        allow_unauth = os.getenv("ICS_ALLOW_UNAUTHENTICATED", "").lower() == "true"
        if not allow_unauth:
            logger.error(
                "ICS_API_KEY not set and ICS_ALLOW_UNAUTHENTICATED is not 'true'. "
                "Set ICS_API_KEY for production or ICS_ALLOW_UNAUTHENTICATED=true for local dev."
            )
            sys.exit(1)

        logger.warning(
            "ICS_API_KEY not set - running in UNAUTHENTICATED mode (not recommended)"
        )

        @app.get("/ics/combined")
        async def combined_noauth(
            request: Request,
            show: Optional[str] = Query(default=None),
            hide: Optional[str] = Query(default=None),
        ) -> Response:
            return _handle_combine_request(request, show, hide)

    return app


app = create_app()

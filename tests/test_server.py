import asyncio
import importlib
import json
import sys
import threading

import httpx
import pytest

from src.services.ics_combiner import ICSCombiner

API_KEY = "test-api-key-1234567890"
SALT = "test-salt"


def _load_server(monkeypatch, authenticated: bool):
    """Import src.server fresh so create_app() sees the patched environment."""
    monkeypatch.delenv("REDIS_HOST", raising=False)
    monkeypatch.setenv(
        "ICS_SOURCES",
        json.dumps([{"Id": 1, "Url": "https://example.invalid/cal.ics"}]),
    )
    if authenticated:
        monkeypatch.setenv("ICS_API_KEY", API_KEY)
        monkeypatch.setenv("SALT", SALT)
        monkeypatch.delenv("ICS_ALLOW_UNAUTHENTICATED", raising=False)
    else:
        monkeypatch.delenv("ICS_API_KEY", raising=False)
        monkeypatch.setenv("ICS_ALLOW_UNAUTHENTICATED", "true")

    if "src.server" in sys.modules:
        return importlib.reload(sys.modules["src.server"])
    return importlib.import_module("src.server")


@pytest.mark.parametrize("authenticated", [True, False], ids=["auth", "noauth"])
def test_health_is_served_while_combine_fetch_is_blocked(monkeypatch, authenticated):
    server = _load_server(monkeypatch, authenticated)
    combine_path = (
        f"/app/{API_KEY}/{server._calc_api_hash(API_KEY, SALT)}/ics"
        if authenticated
        else "/ics/combined"
    )

    fetch_entered = threading.Event()
    release_fetch = threading.Event()
    outcome = {}

    def blocking_fetch(self, source):
        fetch_entered.set()
        # If the combine runs on the event loop, nothing can set release_fetch
        # until this times out, so the health request below never gets served.
        outcome["released_by_health"] = release_fetch.wait(timeout=2)
        return None, False, None

    monkeypatch.setattr(ICSCombiner, "_fetch_source_ics", blocking_fetch)

    async def scenario():
        transport = httpx.ASGITransport(app=server.app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://test"
        ) as client:
            combine = asyncio.create_task(client.get(combine_path))
            assert await asyncio.to_thread(fetch_entered.wait, 5)

            health = await client.get("/app/health")
            release_fetch.set()
            return health, await combine

    health, combine = asyncio.run(scenario())

    assert health.status_code == 200
    assert combine.status_code == 200
    assert outcome[
        "released_by_health"
    ], "/app/health was blocked behind an in-flight combine request"

"""Tests for the cache facade and its memory/PostgreSQL backends.

The postgres parameter runs only when TEST_DATABASE_URL points at a scratch
database (see README.md, "Running the tests"). It drops and recreates the
cache_entries table.
"""

import logging
import os
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

import psycopg
import pytest

from src.services.cache import Cache, MemoryBackend, PostgresBackend

TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@dataclass
class Harness:
    cache: Cache
    advance: Callable[[float], None]


def _drop_table() -> None:
    assert TEST_DATABASE_URL
    with psycopg.connect(TEST_DATABASE_URL, autocommit=True) as conn:
        conn.execute("DROP TABLE IF EXISTS cache_entries")


@pytest.fixture(
    params=[
        "memory",
        pytest.param(
            "postgres",
            marks=pytest.mark.skipif(
                not TEST_DATABASE_URL, reason="TEST_DATABASE_URL not set"
            ),
        ),
    ]
)
def harness(request: pytest.FixtureRequest) -> Iterator[Harness]:
    if request.param == "memory":
        clock = FakeClock()
        yield Harness(Cache(MemoryBackend(clock=clock)), clock.advance)
        return
    assert TEST_DATABASE_URL
    _drop_table()
    cache = Cache(PostgresBackend(TEST_DATABASE_URL))
    yield Harness(cache, time.sleep)
    cache.close()
    _drop_table()


# "" is ics-combiner's negative-cache sentinel: it must come back as "", not a miss.
@pytest.mark.parametrize("value", ["text", "", {"a": [1, 2]}, [1, "x"], 0, False])
def test_round_trip(harness: Harness, value: Any) -> None:
    assert harness.cache.set("k", value, ttl=60)
    assert harness.cache.get("k", default="missing") == value
    assert harness.cache.get("absent", default="missing") == "missing"
    stats = harness.cache.get_stats()
    assert (stats.hits, stats.misses, stats.errors) == (1, 1, 0)


def test_ttl_and_delete(harness: Harness) -> None:
    cache = harness.cache
    assert cache.set("short", "v", ttl=1)
    assert cache.set("forever", "v", ttl=None)
    assert cache.set("zero", "old", ttl=60)
    assert cache.set("zero", "new", ttl=0) is False
    assert cache.set("neg", "v", ttl=-5) is False
    assert cache.get("zero") is None
    assert cache.get("neg") is None
    assert cache.get("short") == "v"
    harness.advance(1.2)
    assert cache.get("short") is None
    assert cache.get("forever") == "v"
    assert cache.delete("forever") is True
    assert cache.delete("forever") is False


def test_upsert_overwrites_value_and_resets_ttl(harness: Harness) -> None:
    cache = harness.cache
    assert cache.set("k", "first", ttl=1)
    assert cache.set("k", "second", ttl=None)
    harness.advance(1.2)
    assert cache.get("k") == "second"
    assert cache.set("k", "third", ttl=1)
    harness.advance(1.2)
    assert cache.get("k") is None


def test_info(harness: Harness) -> None:
    cache = harness.cache
    for key in ("a", "b", "c"):
        assert cache.set(key, key, ttl=60)
    info = cache.info()
    assert info["backend"] in {"memory", "postgres"}
    assert set(info) >= {"server_version", "entries", "expired_pending", "table_bytes"}
    assert info["entries"] == 3


@pytest.mark.skipif(not TEST_DATABASE_URL, reason="TEST_DATABASE_URL not set")
def test_postgres_table_is_logged() -> None:
    # LKG feeds and the sources index have no TTL and must survive a crash.
    assert TEST_DATABASE_URL
    _drop_table()
    cache = Cache(PostgresBackend(TEST_DATABASE_URL))
    try:
        assert cache.set("k", "v", ttl=None)
        with psycopg.connect(TEST_DATABASE_URL) as conn:
            row = conn.execute(
                "SELECT relpersistence FROM pg_class WHERE relname = 'cache_entries'"
            ).fetchone()
        assert row == ("p",)
    finally:
        cache.close()
        _drop_table()


class RaisingBackend:
    name = "stub"

    def is_connected(self) -> bool:
        return True

    def __getattr__(self, attr: str) -> Callable[..., Any]:
        def fail(*_: Any) -> Any:
            raise RuntimeError(f"{attr} exploded")

        return fail


@pytest.mark.parametrize(
    ("call", "expected"),
    [
        (lambda c: c.get("k", default="d"), "d"),
        (lambda c: c.set("k", 1, ttl=5), False),
        (lambda c: c.delete("k"), False),
        (lambda c: c.info(), {"backend": "stub"}),
        (lambda c: c.close(), None),
    ],
)
def test_backend_failures_never_raise(
    call: Callable[[Cache], Any], expected: Any, caplog: pytest.LogCaptureFixture
) -> None:
    cache = Cache(RaisingBackend())  # type: ignore[arg-type]
    assert call(cache) == expected
    call(cache)
    assert cache.get_stats().errors == 2
    # Rate limited: two failures of the same method log once.
    assert len([r for r in caplog.records if r.levelname == "ERROR"]) == 1


class _Result:
    def __init__(self, row: tuple[Any, ...] | None) -> None:
        self._row = row
        self.rowcount = 0 if row is None else 1

    def fetchone(self) -> tuple[Any, ...] | None:
        return self._row


class _FakeConn:
    def __init__(self, store: dict[str, str]) -> None:
        self._store = store

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> _Result:
        if sql.startswith("SELECT value"):
            value = self._store.get(params[0])
            return _Result(None if value is None else (value,))
        if sql.startswith("INSERT"):
            self._store[params[0]] = params[1]
        return _Result(None)


class FlakyPool:
    """Refuses the first `failures` connections, then serves an in-memory table."""

    def __init__(self, failures: int) -> None:
        self.failures = failures
        self.attempts = 0
        self.store: dict[str, str] = {}

    def open(self, wait: bool = False) -> None:
        pass

    @contextmanager
    def connection(self) -> Iterator[_FakeConn]:
        self.attempts += 1
        if self.attempts <= self.failures:
            raise psycopg.OperationalError("connection refused")
        yield _FakeConn(self.store)

    def close(self) -> None:
        pass


def test_database_down_at_startup_recovers_after_backoff(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Regression: a failed connect at startup used to disable caching for the
    # life of the process. Now from_env() always returns a Cache for
    # DATABASE_URL, the first op is a fast miss, and it retries after 30 s.
    monkeypatch.delenv("CACHE_BACKEND", raising=False)
    monkeypatch.setenv("DATABASE_URL", "postgresql://u:pw@127.0.0.1:1/db")
    cache = Cache.from_env()
    assert cache is not None
    backend = cache._backend
    assert isinstance(backend, PostgresBackend)
    clock = FakeClock()
    pool = FlakyPool(failures=1)
    backend._clock = clock
    backend._pool = pool  # type: ignore[assignment]
    backend._schema_ready = True

    assert cache.is_connected()
    assert cache.get("k", default="d") == "d"
    assert cache.get_stats().errors == 1
    assert not cache.is_connected()
    # While backing off, ops short-circuit without touching the pool.
    assert cache.get("k") is None
    assert cache.set("k", "v") is False
    assert pool.attempts == 1

    clock.advance(30)
    assert cache.is_connected()
    assert cache.set("k", "", ttl=60)
    assert cache.get("k") == ""
    assert pool.attempts == 3


@pytest.mark.parametrize(
    ("env", "expected"),
    [
        (
            {"CACHE_BACKEND": "memory", "DATABASE_URL": "postgresql://x/y"},
            MemoryBackend,
        ),
        ({"DATABASE_URL": "postgresql://u:pw@127.0.0.1:1/db"}, PostgresBackend),
        ({}, None),
    ],
)
def test_from_env(
    monkeypatch: pytest.MonkeyPatch, env: dict[str, str], expected: type | None
) -> None:
    monkeypatch.delenv("CACHE_BACKEND", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    cache = Cache.from_env()  # must not attempt a connection
    if expected is None:
        assert cache is None
    else:
        assert cache is not None
        assert isinstance(cache._backend, expected)
        cache.close()


@pytest.mark.parametrize(
    "url", ["postgres://u:PW@[::1/db", "postgresql://u:PW%zz@127.0.0.1:1/db"]
)
def test_malformed_database_url_never_logs_it(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, url: str
) -> None:
    caplog.set_level(logging.DEBUG)
    monkeypatch.delenv("CACHE_BACKEND", raising=False)
    monkeypatch.setenv("DATABASE_URL", url)
    cache = Cache.from_env()
    assert cache is not None
    assert not cache.is_connected()
    assert cache.get("k", default="d") == "d"
    assert cache.set("k", "v") is False
    cache.close()
    assert not [r for r in caplog.records if "PW" in r.getMessage()]
    errors = [r.getMessage() for r in caplog.records if r.levelname == "ERROR"]
    assert len(errors) == 1
    assert "DATABASE_URL is not a valid libpq connection string" in errors[0]


def test_pool_connect_errors_are_not_logged(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    cache = Cache(PostgresBackend("postgresql://u:PW@127.0.0.1:1/db"))
    assert cache.get("k", default="d") == "d"  # waits out the 2 s pool timeout
    cache.close()
    pool_records = [r for r in caplog.records if r.name == "psycopg.pool"]
    assert not [
        r for r in pool_records if r.getMessage().startswith("error connecting")
    ]
    assert len([r for r in caplog.records if r.name == "src.services.cache"]) == 1

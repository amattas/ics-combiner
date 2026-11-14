"""Cache layer for ICS Combiner.

`Cache` is the facade the app uses. It serializes values as JSON, keeps
hit/miss statistics, and never raises into the request path: backend errors are
logged (rate limited), counted in `CacheStats.errors`, and turned into misses.

Backends:
- `PostgresBackend`: a table in the service's own PostgreSQL database
  (`DATABASE_URL`). Connects lazily, backs off for 30 s after any database
  error, and creates its table on first use.
- `MemoryBackend`: a process-local dict for local development and tests
  (`CACHE_BACKEND=memory`).
"""

import json
import logging
import os
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Protocol

import psycopg
from psycopg_pool import ConnectionPool, PoolTimeout

logger = logging.getLogger(__name__)

APPLICATION_NAME = "ics-combiner"


@dataclass
class CacheStats:
    """Cache performance metrics"""

    hits: int = 0
    misses: int = 0
    errors: int = 0
    total_requests: int = 0
    hit_time_sum: float = 0.0
    miss_time_sum: float = 0.0
    last_reset: float = field(default_factory=time.time)

    @property
    def hit_rate(self) -> float:
        if self.total_requests == 0:
            return 0.0
        return self.hits / self.total_requests

    @property
    def miss_rate(self) -> float:
        if self.total_requests == 0:
            return 0.0
        return self.misses / self.total_requests

    @property
    def avg_hit_time(self) -> float:
        """Average time for cache hits in milliseconds"""
        if self.hits == 0:
            return 0.0
        return (self.hit_time_sum / self.hits) * 1000

    @property
    def avg_miss_time(self) -> float:
        """Average time for cache misses in milliseconds"""
        if self.misses == 0:
            return 0.0
        return (self.miss_time_sum / self.misses) * 1000

    def to_dict(self) -> dict[str, Any]:
        return {
            "hits": self.hits,
            "misses": self.misses,
            "errors": self.errors,
            "total_requests": self.total_requests,
            "hit_rate": self.hit_rate,
            "miss_rate": self.miss_rate,
            "avg_hit_time_ms": self.avg_hit_time,
            "avg_miss_time_ms": self.avg_miss_time,
            "uptime_seconds": time.time() - self.last_reset,
        }


class CacheBackend(Protocol):
    """Storage behind `Cache`. Values are already-serialized JSON text."""

    name: str

    def is_connected(self) -> bool: ...
    def get(self, key: str) -> str | None: ...
    def set(self, key: str, value: str, ttl: int | None) -> None: ...
    def delete(self, key: str) -> bool: ...
    def info(self) -> dict[str, Any]: ...
    def close(self) -> None: ...


class MemoryBackend:
    """Process-local backend for local development and tests."""

    name = "memory"

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._data: dict[str, tuple[str, float | None]] = {}
        self._lock = threading.Lock()

    def _live(self, entry: tuple[str, float | None], now: float) -> bool:
        return entry[1] is None or entry[1] > now

    def is_connected(self) -> bool:
        return True

    def get(self, key: str) -> str | None:
        with self._lock:
            entry = self._data.get(key)
            if entry is None:
                return None
            if not self._live(entry, self._clock()):
                del self._data[key]
                return None
            return entry[0]

    def set(self, key: str, value: str, ttl: int | None) -> None:
        expires = None if ttl is None else self._clock() + ttl
        with self._lock:
            self._data[key] = (value, expires)

    def delete(self, key: str) -> bool:
        with self._lock:
            return self._data.pop(key, None) is not None

    def info(self) -> dict[str, Any]:
        with self._lock:
            now = self._clock()
            expired = sum(1 for e in self._data.values() if not self._live(e, now))
            return {
                "server_version": None,
                "entries": len(self._data),
                "expired_pending": expired,
                "table_bytes": None,
            }

    def close(self) -> None:
        pass


# A logged table, unlike the UNLOGGED one in the MCP servers' copies of this
# module: ics-combiner stores last-known-good (LKG) feeds and the sources index
# with no TTL, so they must survive a database crash and a failover.
_TABLE_KIND = "TABLE"
_SCHEMA_LOCK_ID = 727001
_BACKOFF_SECONDS = 30.0
_SWEEP_EVERY = 50

_SQL_LOCK = "SELECT pg_advisory_xact_lock(%s)"
_SQL_CREATE_TABLE = (
    f"CREATE {_TABLE_KIND} IF NOT EXISTS cache_entries "
    "(key text PRIMARY KEY, value text NOT NULL, expires_at timestamptz)"
)
_SQL_CREATE_INDEX = (
    "CREATE INDEX IF NOT EXISTS cache_entries_expires_idx "
    "ON cache_entries (expires_at) WHERE expires_at IS NOT NULL"
)
_SQL_GET = (
    "SELECT value FROM cache_entries "
    "WHERE key = %s AND (expires_at IS NULL OR expires_at > now())"
)
_SQL_SET = (
    "INSERT INTO cache_entries (key, value, expires_at) "
    "VALUES (%s, %s, now() + %s::double precision * interval '1 second') "
    "ON CONFLICT (key) DO UPDATE "
    "SET value = EXCLUDED.value, expires_at = EXCLUDED.expires_at"
)
_SQL_DELETE = "DELETE FROM cache_entries WHERE key = %s"
_SQL_SWEEP = (
    "DELETE FROM cache_entries WHERE key IN (SELECT key FROM cache_entries "
    "WHERE expires_at IS NOT NULL AND expires_at <= now() LIMIT 500)"
)
_SQL_INFO = (
    "SELECT version(), (SELECT count(*) FROM cache_entries), "
    "(SELECT count(*) FROM cache_entries "
    "WHERE expires_at IS NOT NULL AND expires_at <= now()), "
    "pg_total_relation_size('cache_entries')"
)


class PostgresBackend:
    """Cache table in PostgreSQL via a small sync connection pool.

    Constructing it does no I/O. The pool opens on the first operation, the
    table is created once per process after the first successful connect, and
    any database error starts a 30 s backoff during which every operation is a
    miss and `is_connected()` is False (it never does I/O itself).
    """

    name = "postgres"

    def __init__(
        self, conninfo: str, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self._clock = clock
        self._pool = ConnectionPool(
            conninfo,
            min_size=1,
            max_size=3,
            timeout=2,
            open=False,
            kwargs={
                "connect_timeout": 3,
                "options": "-c statement_timeout=3000",
                "autocommit": True,
                "application_name": APPLICATION_NAME,
            },
            check=ConnectionPool.check_connection,
        )
        self._lock = threading.Lock()
        self._opened = False
        self._schema_ready = False
        self._down_until = 0.0
        self._sets = 0

    def is_connected(self) -> bool:
        return self._clock() >= self._down_until

    @contextmanager
    def _connection(self) -> Iterator[psycopg.Connection[Any]]:
        try:
            with self._lock:
                if not self._opened:
                    self._pool.open(wait=False)
                    self._opened = True
            with self._pool.connection() as conn:
                if not self._schema_ready:
                    self._ensure_schema(conn)
                yield conn
        except psycopg.Error, PoolTimeout:
            self._down_until = self._clock() + _BACKOFF_SECONDS
            raise

    def _ensure_schema(self, conn: psycopg.Connection[Any]) -> None:
        with self._lock:
            if self._schema_ready:
                return
            try:
                with conn.transaction():
                    conn.execute(_SQL_LOCK, (_SCHEMA_LOCK_ID,))
                    conn.execute(_SQL_CREATE_TABLE)
                    conn.execute(_SQL_CREATE_INDEX)
            except psycopg.errors.InsufficientPrivilege:
                logger.warning(
                    "Cache table cannot be created: role %r lacks CREATE on schema "
                    "public. Fix as postgres: GRANT ALL ON SCHEMA public TO %s",
                    conn.info.user,
                    conn.info.user,
                )
                raise
            self._schema_ready = True

    def get(self, key: str) -> str | None:
        if not self.is_connected():
            return None
        with self._connection() as conn:
            row = conn.execute(_SQL_GET, (key,)).fetchone()
        return None if row is None else str(row[0])

    def set(self, key: str, value: str, ttl: int | None) -> None:
        if not self.is_connected():
            return
        with self._connection() as conn:
            conn.execute(_SQL_SET, (key, value, ttl))
            self._sets += 1
            if self._sets % _SWEEP_EVERY == 0:
                conn.execute(_SQL_SWEEP)

    def delete(self, key: str) -> bool:
        if not self.is_connected():
            return False
        with self._connection() as conn:
            return conn.execute(_SQL_DELETE, (key,)).rowcount > 0

    def info(self) -> dict[str, Any]:
        if not self.is_connected():
            return {}
        with self._connection() as conn:
            row = conn.execute(_SQL_INFO).fetchone()
        if row is None:
            return {}
        version, entries, expired, size = row
        return {
            "server_version": version,
            "entries": entries,
            "expired_pending": expired,
            "table_bytes": size,
        }

    def close(self) -> None:
        with self._lock:
            if self._opened:
                self._pool.close()
                self._opened = False


_ERROR_LOG_INTERVAL = 60.0


class Cache:
    """Cache facade: JSON values, statistics, and a never-raise error contract."""

    def __init__(self, backend: CacheBackend) -> None:
        self._backend = backend
        self.stats = CacheStats()
        self._last_error_log: dict[str, float] = {}

    @classmethod
    def from_env(cls) -> Cache | None:
        """`CACHE_BACKEND=memory`, else `DATABASE_URL`, else no cache.

        Does not connect: the PostgreSQL pool opens on first use, so a database
        that is down at startup only means misses until it comes back.
        """
        if os.getenv("CACHE_BACKEND", "").strip().lower() == "memory":
            return cls(MemoryBackend())
        url = os.getenv("DATABASE_URL")
        if url:
            return cls(PostgresBackend(url))
        return None

    def _failed(self, method: str, exc: Exception) -> None:
        self.stats.errors += 1
        now = time.monotonic()
        last = self._last_error_log.get(method)
        if last is None or now - last >= _ERROR_LOG_INTERVAL:
            self._last_error_log[method] = now
            logger.error(
                "Cache %s failed (%s backend): %s: %s",
                method,
                self._backend.name,
                type(exc).__name__,
                exc,
            )

    def is_connected(self) -> bool:
        """True unless the backend is backing off after an error (no I/O)."""
        try:
            return self._backend.is_connected()
        except Exception as e:
            self._failed("is_connected", e)
            return False

    def get(self, key: str, default: Any = None) -> Any:
        start = time.perf_counter()
        try:
            data = self._backend.get(key)
            value = default if data is None else json.loads(data)
        except Exception as e:
            self._failed("get", e)
            return default
        elapsed = time.perf_counter() - start
        self.stats.total_requests += 1
        if data is None:
            self.stats.misses += 1
            self.stats.miss_time_sum += elapsed
        else:
            self.stats.hits += 1
            self.stats.hit_time_sum += elapsed
        return value

    def set(self, key: str, value: Any, ttl: int | None = None) -> bool:
        """Store `value` for `ttl` seconds (None: no expiry; <= 0: delete, False)."""
        try:
            if ttl is not None and ttl <= 0:
                self._backend.delete(key)
                return False
            if not self._backend.is_connected():
                return False
            self._backend.set(key, json.dumps(value), ttl)
            return True
        except Exception as e:
            self._failed("set", e)
            return False

    def delete(self, key: str) -> bool:
        try:
            return self._backend.delete(key)
        except Exception as e:
            self._failed("delete", e)
            return False

    def info(self) -> dict[str, Any]:
        """Backend name plus server_version, entries, expired_pending, table_bytes."""
        try:
            return {"backend": self._backend.name, **self._backend.info()}
        except Exception as e:
            self._failed("info", e)
            return {"backend": self._backend.name}

    def get_stats(self) -> CacheStats:
        return self.stats

    def close(self) -> None:
        try:
            self._backend.close()
        except Exception as e:
            self._failed("close", e)


def _get_cache_ttl(env_var: str, default: int, minimum: int = 0) -> int:
    env_value = os.getenv(f"CACHE_TTL_{env_var}")
    if env_value:
        try:
            value = int(env_value)
            if value < minimum:
                logger.warning(
                    f"Invalid TTL for CACHE_TTL_{env_var}: {value} "
                    f"(minimum: {minimum}), using default: {default}"
                )
                return default
            return value
        except ValueError:
            logger.warning(
                f"Invalid TTL value for CACHE_TTL_{env_var}: {env_value}, using default: {default}"
            )
    return default


def _get_optional_cache_ttl(env_var: str) -> int | None:
    env_value = os.getenv(f"CACHE_TTL_{env_var}")
    if env_value is None or env_value == "":
        return None

    try:
        value = int(env_value)
    except ValueError:
        logger.warning(
            f"Invalid TTL value for CACHE_TTL_{env_var}: {env_value}, using no expiration"
        )
        return None

    if value < 0:
        logger.warning(
            f"Invalid TTL for CACHE_TTL_{env_var}: {value} "
            "(`0` means no expiration), using no expiration"
        )
        return None

    if value == 0:
        return None

    return value


class CacheTTL:
    # Default TTL for ICS source caching
    ICS_SOURCE_DEFAULT = _get_cache_ttl("ICS_SOURCE_DEFAULT", 600)
    # Last-known-good fallback TTL. Unset/0 means retain indefinitely.
    ICS_SOURCE_LKG = _get_optional_cache_ttl("ICS_SOURCE_LKG")
    # Backoff TTL for failed source fetches
    ICS_SOURCE_FAILURE_BACKOFF = _get_cache_ttl(
        "ICS_SOURCE_FAILURE_BACKOFF", 60, minimum=1
    )
    # Backoff TTL for HTTP 429 responses that lack a Retry-After header
    ICS_SOURCE_RATE_LIMIT_BACKOFF = _get_cache_ttl(
        "ICS_SOURCE_RATE_LIMIT_BACKOFF", 3600, minimum=1
    )

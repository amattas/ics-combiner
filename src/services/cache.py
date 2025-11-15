"""Redis caching layer for ICS Combiner services (borrowed from MCP servers)"""

import os
import json
import logging
import time
from typing import Any, Optional, Dict, Callable, TypeVar
from functools import wraps
from dataclasses import dataclass, field
import redis
from redis import Redis, ConnectionPool, RedisError
from redis.connection import SSLConnection
import ssl  # noqa: F401  # kept for compatibility if SSL kwargs are extended

logger = logging.getLogger(__name__)

T = TypeVar('T')


@dataclass
class CacheStats:
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
        if self.hits == 0:
            return 0.0
        return (self.hit_time_sum / self.hits) * 1000

    @property
    def avg_miss_time(self) -> float:
        if self.misses == 0:
            return 0.0
        return (self.miss_time_sum / self.misses) * 1000

    def to_dict(self) -> Dict[str, Any]:
        return {
            'hits': self.hits,
            'misses': self.misses,
            'errors': self.errors,
            'total_requests': self.total_requests,
            'hit_rate': self.hit_rate,
            'miss_rate': self.miss_rate,
            'avg_hit_time_ms': self.avg_hit_time,
            'avg_miss_time_ms': self.avg_miss_time,
            'uptime_seconds': time.time() - self.last_reset
        }

    def reset(self):
        self.hits = 0
        self.misses = 0
        self.errors = 0
        self.total_requests = 0
        self.hit_time_sum = 0.0
        self.miss_time_sum = 0.0
        self.last_reset = time.time()


@dataclass
class CacheConfig:
    ttl: int = 300
    key_prefix: str = ""
    version: str = "v1"

    def get_ttl_seconds(self) -> int:
        return self.ttl


class RedisCache:
    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        password: Optional[str] = None,
        use_ssl: bool = True,
        ssl_cert_reqs: str = 'required',
        max_connections: int = 50,
        connection_timeout: int = 5,
        socket_timeout: int = 5,
        retry_on_timeout: bool = True,
        health_check_interval: int = 30
    ):
        self.host = host or os.getenv('REDIS_HOST')
        self.port = int(port or os.getenv('REDIS_SSL_PORT', '6380'))
        self.password = password or os.getenv('REDIS_KEY')
        self.use_ssl = use_ssl

        if not self.host:
            raise ValueError("Redis host is required (set REDIS_HOST env var)")

        pool_kwargs = {
            'host': self.host,
            'port': self.port,
            'password': self.password,
            'max_connections': max_connections,
            'connection_class': SSLConnection if use_ssl else redis.Connection,
            'socket_connect_timeout': connection_timeout,
            'socket_timeout': socket_timeout,
            'retry_on_timeout': retry_on_timeout,
            'health_check_interval': health_check_interval,
        }

        if use_ssl:
            pool_kwargs['ssl_cert_reqs'] = ssl_cert_reqs
            pool_kwargs['ssl_ca_certs'] = None

        self.pool = ConnectionPool(**pool_kwargs)
        self.client: Optional[Redis] = None
        self.stats = CacheStats()
        self._connected = False
        self._connect()

    def _connect(self) -> bool:
        try:
            self.client = Redis(connection_pool=self.pool)
            self.client.ping()
            self._connected = True
            logger.info(f"Connected to Redis at {self.host}:{self.port} (SSL: {self.use_ssl})")
            return True
        except (RedisError, Exception) as e:
            logger.error(f"Failed to connect to Redis: {e}")
            self._connected = False
            return False

    @classmethod
    def from_env(cls) -> Optional['RedisCache']:
        try:
            return cls()
        except (ValueError, RedisError) as e:
            logger.warning(f"Redis cache not available: {e}")
            return None

    def is_connected(self) -> bool:
        if not self._connected or not self.client:
            return False
        try:
            self.client.ping()
            return True
        except (RedisError, Exception):
            self._connected = False
            return False

    def get(self, key: str, default: Any = None) -> Any:
        if not self.is_connected():
            self.stats.errors += 1
            return default

        self.stats.total_requests += 1
        start = time.time()
        try:
            data = self.client.get(key)
            elapsed = time.time() - start
            if data is not None:
                self.stats.hits += 1
                self.stats.hit_time_sum += elapsed
                return json.loads(data.decode('utf-8'))
            else:
                self.stats.misses += 1
                self.stats.miss_time_sum += elapsed
                return default
        except (RedisError, Exception) as e:
            logger.error(f"Cache get error for key {key}: {e}")
            self.stats.errors += 1
            return default

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        if not self.is_connected():
            return False
        try:
            serialized = json.dumps(value, default=str).encode('utf-8')
            kwargs = {'ex': ttl} if ttl is not None else {}
            result = self.client.set(key, serialized, **kwargs)
            return bool(result)
        except (RedisError, Exception) as e:
            logger.error(f"Cache set error for key {key}: {e}")
            self.stats.errors += 1
            return False

    def delete(self, key: str) -> bool:
        if not self.is_connected():
            return False
        try:
            return bool(self.client.delete(key))
        except (RedisError, Exception) as e:
            logger.error(f"Cache delete error for key {key}: {e}")
            return False


def _get_cache_ttl(env_var: str, default: int) -> int:
    env_value = os.getenv(f"CACHE_TTL_{env_var}")
    if env_value:
        try:
            value = int(env_value)
            if value < 0:
                logger.warning(f"Invalid negative TTL for CACHE_TTL_{env_var}: {value}, using default: {default}")
                return default
            return value
        except ValueError:
            logger.warning(f"Invalid TTL value for CACHE_TTL_{env_var}: {env_value}, using default: {default}")
    return default


class CacheTTL:
    # Default TTL for ICS source caching
    ICS_SOURCE_DEFAULT = _get_cache_ttl("ICS_SOURCE_DEFAULT", 600)


import requests
from icalendar import Calendar

from src.services.cache import CacheStats, CacheTTL, RedisCache, _get_cache_ttl
from src.services.ics_combiner import ICSCombiner

VALID_ICS = """BEGIN:VCALENDAR
VERSION:2.0
BEGIN:VEVENT
UID:event-1
DTSTART:20300101T120000Z
SUMMARY:Cached event
END:VEVENT
END:VCALENDAR
"""

VALID_ICS_UPDATED = """BEGIN:VCALENDAR
VERSION:2.0
BEGIN:VEVENT
UID:event-2
DTSTART:20300102T120000Z
SUMMARY:Updated event
END:VEVENT
END:VCALENDAR
"""

INVALID_ICS = "<html>temporary upstream error</html>"


class FakeResponse:
    def __init__(self, text: str):
        self.text = text
        self._content = text.encode("utf-8")

    def raise_for_status(self):
        return None

    def iter_content(self, chunk_size=8192, decode_unicode=False):
        for i in range(0, len(self._content), chunk_size):
            yield self._content[i : i + chunk_size]

    def close(self):
        pass


class MemoryCache:
    def __init__(self):
        self.store = {}
        self.set_calls = []
        self.deleted = []

    def is_connected(self):
        return True

    def get(self, key, default=None):
        return self.store.get(key, default)

    def set(self, key, value, ttl=None):
        self.set_calls.append((key, value, ttl))
        if ttl is not None and ttl <= 0:
            self.store.pop(key, None)
            return True
        self.store[key] = value
        return True

    def delete(self, key):
        self.deleted.append(key)
        self.store.pop(key, None)
        return True


class FakeRedisClient:
    def __init__(self):
        self.deleted = []
        self.set_calls = []

    def ping(self):
        return True

    def delete(self, key):
        self.deleted.append(key)
        return 1

    def set(self, *args, **kwargs):
        self.set_calls.append((args, kwargs))
        return True


def test_redis_set_with_zero_ttl_expires_without_invalid_ex_argument():
    client = FakeRedisClient()
    cache = RedisCache.__new__(RedisCache)
    cache.client = client
    cache.stats = CacheStats()
    cache._connected = True

    assert cache.set("ics:source:1", "value", ttl=0)
    assert client.deleted == ["ics:source:1"]
    assert client.set_calls == []


def test_failure_backoff_ttl_rejects_zero(monkeypatch):
    monkeypatch.setenv("CACHE_TTL_ICS_SOURCE_FAILURE_BACKOFF", "0")

    assert _get_cache_ttl("ICS_SOURCE_FAILURE_BACKOFF", 60, minimum=1) == 60


def test_last_known_good_ttl_rejects_zero(monkeypatch):
    monkeypatch.setenv("CACHE_TTL_ICS_SOURCE_LKG", "0")

    assert _get_cache_ttl("ICS_SOURCE_LKG", 86400, minimum=1) == 86400


def test_fetch_without_cache_success(monkeypatch):
    source = {"Id": 1, "Url": "https://example.com/calendar.ics"}
    combiner = ICSCombiner(cache=None)

    monkeypatch.setattr(
        "src.services.ics_combiner.requests.get",
        lambda *_args, **_kwargs: FakeResponse(VALID_ICS),
    )

    ics_text, is_stale = combiner.fetch_source_ics(source)

    assert ics_text == VALID_ICS
    assert is_stale is False


def test_fetch_without_cache_failure(monkeypatch):
    source = {"Id": 1, "Url": "https://example.com/calendar.ics"}
    combiner = ICSCombiner(cache=None)

    def raise_request_exception(*_args, **_kwargs):
        raise requests.RequestException("upstream unavailable")

    monkeypatch.setattr(
        "src.services.ics_combiner.requests.get",
        raise_request_exception,
    )

    ics_text, is_stale = combiner.fetch_source_ics(source)

    assert ics_text is None
    assert is_stale is False


def test_fetch_cache_hit_skips_network(monkeypatch):
    cache = MemoryCache()
    source = {"Id": 1, "Url": "https://example.com/calendar.ics"}
    combiner = ICSCombiner(cache=cache)
    cache_key = combiner._cache_key_for_source(source)
    cache.store[cache_key] = VALID_ICS

    def fail_get(*_args, **_kwargs):
        raise AssertionError("network should not be called on cache hit")

    monkeypatch.setattr("src.services.ics_combiner.requests.get", fail_get)

    ics_text, is_stale = combiner.fetch_source_ics(source)

    assert ics_text == VALID_ICS
    assert is_stale is False


def test_combine_reuses_calendar_parsed_during_fetch(monkeypatch):
    cache = MemoryCache()
    source = {"Id": 1, "Url": "https://example.com/calendar.ics"}
    combiner = ICSCombiner(cache=cache)
    cache_key = combiner._cache_key_for_source(source)
    cache.store[cache_key] = VALID_ICS
    parse_calls = []
    original_from_ical = Calendar.from_ical

    def counted_from_ical(*args, **kwargs):
        parse_calls.append(args[0])
        return original_from_ical(*args, **kwargs)

    def fail_get(*_args, **_kwargs):
        raise AssertionError("network should not be called on cache hit")

    monkeypatch.setattr(
        "src.services.ics_combiner.Calendar.from_ical", counted_from_ical
    )
    monkeypatch.setattr("src.services.ics_combiner.requests.get", fail_get)

    combined = combiner.combine([source], "Combined", days_history=0)

    assert b"SUMMARY:Cached event" in combined
    assert parse_calls == [VALID_ICS]


def test_successful_fetch_sets_primary_and_last_known_good_cache(monkeypatch):
    cache = MemoryCache()
    source = {
        "Id": 1,
        "Url": "https://example.com/calendar.ics",
        "RefreshSeconds": 123,
    }
    combiner = ICSCombiner(cache=cache)
    cache_key = combiner._cache_key_for_source(source)
    lkg_key = f"{cache_key}:lkg"

    monkeypatch.setattr(
        "src.services.ics_combiner.requests.get",
        lambda *_args, **_kwargs: FakeResponse(VALID_ICS),
    )

    ics_text, is_stale = combiner.fetch_source_ics(source)

    assert ics_text == VALID_ICS
    assert is_stale is False
    assert (cache_key, VALID_ICS, 123) in cache.set_calls
    assert (lkg_key, VALID_ICS, CacheTTL.ICS_SOURCE_LKG) in cache.set_calls


def test_fetch_failure_negative_caches_and_serves_last_known_good(monkeypatch):
    cache = MemoryCache()
    source = {
        "Id": 1,
        "Url": "https://example.com/calendar.ics",
        "RefreshSeconds": 77,
    }
    combiner = ICSCombiner(cache=cache)
    cache_key = combiner._cache_key_for_source(source)
    cache.store[f"{cache_key}:lkg"] = VALID_ICS

    def raise_request_exception(*_args, **_kwargs):
        raise requests.RequestException("upstream unavailable")

    monkeypatch.setattr(
        "src.services.ics_combiner.requests.get",
        raise_request_exception,
    )

    ics_text, is_stale = combiner.fetch_source_ics(source)

    assert ics_text == VALID_ICS
    assert is_stale is True
    assert (cache_key, "", CacheTTL.ICS_SOURCE_FAILURE_BACKOFF) in cache.set_calls


def test_zero_refresh_seconds_still_backs_off_failures(monkeypatch):
    cache = MemoryCache()
    source = {
        "Id": 1,
        "Url": "https://example.com/calendar.ics",
        "RefreshSeconds": 0,
    }
    combiner = ICSCombiner(cache=cache)
    cache_key = combiner._cache_key_for_source(source)
    cache.store[f"{cache_key}:lkg"] = VALID_ICS

    def raise_request_exception(*_args, **_kwargs):
        raise requests.RequestException("upstream unavailable")

    monkeypatch.setattr(
        "src.services.ics_combiner.requests.get",
        raise_request_exception,
    )

    ics_text, is_stale = combiner.fetch_source_ics(source)

    assert ics_text == VALID_ICS
    assert is_stale is True
    assert (cache_key, "", CacheTTL.ICS_SOURCE_FAILURE_BACKOFF) in cache.set_calls
    assert cache.store[cache_key] == ""


def test_negative_cache_hit_skips_network_and_serves_last_known_good(monkeypatch):
    cache = MemoryCache()
    source = {"Id": 1, "Url": "https://example.com/calendar.ics"}
    combiner = ICSCombiner(cache=cache)
    cache_key = combiner._cache_key_for_source(source)
    cache.store[cache_key] = ""
    cache.store[f"{cache_key}:lkg"] = VALID_ICS

    def fail_get(*_args, **_kwargs):
        raise AssertionError("network should not be called on negative cache hit")

    monkeypatch.setattr("src.services.ics_combiner.requests.get", fail_get)

    ics_text, is_stale = combiner.fetch_source_ics(source)

    assert ics_text == VALID_ICS
    assert is_stale is True


def test_lkg_cache_hit_does_not_renormalize(monkeypatch):
    cache = MemoryCache()
    source = {"Id": 1, "Url": "https://example.com/calendar.ics"}
    combiner = ICSCombiner(cache=cache)
    cache_key = combiner._cache_key_for_source(source)
    cache.store[cache_key] = ""
    cache.store[f"{cache_key}:lkg"] = VALID_ICS

    def fail_normalize(_ics_text):
        raise AssertionError("stored last-known-good ICS should not be renormalized")

    def fail_get(*_args, **_kwargs):
        raise AssertionError("network should not be called on negative cache hit")

    monkeypatch.setattr(
        ICSCombiner, "_normalize_ics_text", staticmethod(fail_normalize)
    )
    monkeypatch.setattr("src.services.ics_combiner.requests.get", fail_get)

    ics_text, is_stale = combiner.fetch_source_ics(source)

    assert ics_text == VALID_ICS
    assert is_stale is True


def test_invalid_http_200_does_not_replace_last_known_good_cache(monkeypatch):
    cache = MemoryCache()
    source = {
        "Id": 1,
        "Url": "https://example.com/calendar.ics",
        "RefreshSeconds": 88,
    }
    combiner = ICSCombiner(cache=cache)
    cache_key = combiner._cache_key_for_source(source)
    lkg_key = f"{cache_key}:lkg"
    cache.store[lkg_key] = VALID_ICS

    monkeypatch.setattr(
        "src.services.ics_combiner.requests.get",
        lambda *_args, **_kwargs: FakeResponse(INVALID_ICS),
    )

    ics_text, is_stale = combiner.fetch_source_ics(source)

    assert ics_text == VALID_ICS
    assert is_stale is True
    assert (cache_key, "", CacheTTL.ICS_SOURCE_FAILURE_BACKOFF) in cache.set_calls
    assert cache.store[lkg_key] == VALID_ICS


def test_invalid_primary_cache_entry_is_deleted_and_refetched(monkeypatch):
    cache = MemoryCache()
    source = {"Id": 1, "Url": "https://example.com/calendar.ics"}
    combiner = ICSCombiner(cache=cache)
    cache_key = combiner._cache_key_for_source(source)
    cache.store[cache_key] = INVALID_ICS
    calls = []

    def get(url, timeout, **kwargs):
        calls.append((url, timeout))
        return FakeResponse(VALID_ICS_UPDATED)

    monkeypatch.setattr("src.services.ics_combiner.requests.get", get)

    ics_text, is_stale = combiner.fetch_source_ics(source)

    assert ics_text == VALID_ICS_UPDATED
    assert is_stale is False
    assert cache.deleted == [cache_key]
    assert calls == [(source["Url"], 15)]

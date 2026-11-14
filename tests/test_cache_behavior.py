import json

import pytest
import requests
from icalendar import Calendar
from requests.structures import CaseInsensitiveDict

from src.services.cache import (
    Cache,
    CacheTTL,
    MemoryBackend,
    _get_cache_ttl,
    _get_optional_cache_ttl,
)
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
    def __init__(self, text: str = "", status_code: int = 200, headers=None):
        self.text = text
        self._content = text.encode("utf-8")
        self.status_code = status_code
        self.headers = CaseInsensitiveDict(headers or {})

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"{self.status_code} error", response=self)

    def iter_content(self, chunk_size=8192, decode_unicode=False):
        for i in range(0, len(self._content), chunk_size):
            yield self._content[i : i + chunk_size]

    def close(self):
        pass


class RecordingBackend(MemoryBackend):
    """MemoryBackend that also records the writes the combiner makes."""

    def __init__(self):
        super().__init__()
        self.set_calls = []
        self.deleted = []

    def set(self, key, value, ttl):
        self.set_calls.append((key, json.loads(value), ttl))
        super().set(key, value, ttl)

    def delete(self, key):
        self.deleted.append(key)
        return super().delete(key)

    def seed(self, key, value):
        """Pre-populate an entry (no expiry) without recording it as a write."""
        super().set(key, json.dumps(value), None)


@pytest.fixture
def backend():
    return RecordingBackend()


@pytest.fixture
def cache(backend):
    return Cache(backend)


def test_failure_backoff_ttl_rejects_zero(monkeypatch):
    monkeypatch.setenv("CACHE_TTL_ICS_SOURCE_FAILURE_BACKOFF", "0")

    assert _get_cache_ttl("ICS_SOURCE_FAILURE_BACKOFF", 60, minimum=1) == 60


def test_cache_key_uses_explicit_namespace(monkeypatch):
    monkeypatch.setenv("ICS_CACHE_NAMESPACE", "family calendar")
    combiner = ICSCombiner(cache=None)
    source = {"Id": 1, "Url": "https://example.com/calendar.ics"}

    assert combiner.cache_namespace == "family_calendar"
    assert combiner._cache_key_for_source(source).startswith(
        "ics:family_calendar:source:1:"
    )


def test_cache_namespace_can_be_derived_from_api_key(monkeypatch):
    monkeypatch.delenv("ICS_CACHE_NAMESPACE", raising=False)
    monkeypatch.delenv("CACHE_KEY_PREFIX", raising=False)
    monkeypatch.setenv("ICS_API_KEY", "secret-api-key-123456")

    combiner = ICSCombiner(cache=None)
    source = {"Id": 1, "Url": "https://example.com/calendar.ics"}
    cache_key = combiner._cache_key_for_source(source)

    assert combiner.cache_namespace.startswith("app:")
    assert cache_key.startswith("ics:app:")
    assert "secret-api-key" not in cache_key


def test_last_known_good_ttl_defaults_to_no_expiration(monkeypatch):
    monkeypatch.delenv("CACHE_TTL_ICS_SOURCE_LKG", raising=False)

    assert _get_optional_cache_ttl("ICS_SOURCE_LKG") is None


def test_last_known_good_ttl_zero_means_no_expiration(monkeypatch):
    monkeypatch.setenv("CACHE_TTL_ICS_SOURCE_LKG", "0")

    assert _get_optional_cache_ttl("ICS_SOURCE_LKG") is None


def test_last_known_good_ttl_accepts_positive_override(monkeypatch):
    monkeypatch.setenv("CACHE_TTL_ICS_SOURCE_LKG", "604800")

    assert _get_optional_cache_ttl("ICS_SOURCE_LKG") == 604800


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


def test_fetch_cache_hit_skips_network(monkeypatch, cache, backend):
    source = {"Id": 1, "Url": "https://example.com/calendar.ics"}
    combiner = ICSCombiner(cache=cache)
    cache_key = combiner._cache_key_for_source(source)
    backend.seed(cache_key, VALID_ICS)

    def fail_get(*_args, **_kwargs):
        raise AssertionError("network should not be called on cache hit")

    monkeypatch.setattr("src.services.ics_combiner.requests.get", fail_get)

    ics_text, is_stale = combiner.fetch_source_ics(source)

    assert ics_text == VALID_ICS
    assert is_stale is False


def test_combine_reuses_calendar_parsed_during_fetch(monkeypatch, cache, backend):
    source = {"Id": 1, "Url": "https://example.com/calendar.ics"}
    combiner = ICSCombiner(cache=cache)
    cache_key = combiner._cache_key_for_source(source)
    backend.seed(cache_key, VALID_ICS)
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


def test_successful_fetch_sets_primary_and_last_known_good_cache(
    monkeypatch, cache, backend
):
    monkeypatch.setattr(CacheTTL, "ICS_SOURCE_LKG", None)
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
    assert (cache_key, VALID_ICS, 123) in backend.set_calls
    assert (lkg_key, VALID_ICS, CacheTTL.ICS_SOURCE_LKG) in backend.set_calls
    assert CacheTTL.ICS_SOURCE_LKG is None


def test_primary_cache_hit_backfills_last_known_good_without_expiration(
    monkeypatch, cache, backend
):
    monkeypatch.setattr(CacheTTL, "ICS_SOURCE_LKG", None)
    source = {"Id": 1, "Url": "https://example.com/calendar.ics"}
    combiner = ICSCombiner(cache=cache)
    cache_key = combiner._cache_key_for_source(source)
    lkg_key = f"{cache_key}:lkg"
    backend.seed(cache_key, VALID_ICS)

    def fail_get(*_args, **_kwargs):
        raise AssertionError("network should not be called on cache hit")

    monkeypatch.setattr("src.services.ics_combiner.requests.get", fail_get)

    ics_text, is_stale = combiner.fetch_source_ics(source)

    assert ics_text == VALID_ICS
    assert is_stale is False
    assert (lkg_key, VALID_ICS, None) in backend.set_calls


def test_fetch_failure_negative_caches_and_serves_last_known_good(
    monkeypatch, cache, backend
):
    monkeypatch.setattr(CacheTTL, "ICS_SOURCE_LKG", None)
    source = {
        "Id": 1,
        "Url": "https://example.com/calendar.ics",
        "RefreshSeconds": 77,
    }
    combiner = ICSCombiner(cache=cache)
    cache_key = combiner._cache_key_for_source(source)
    backend.seed(f"{cache_key}:lkg", VALID_ICS)

    def raise_request_exception(*_args, **_kwargs):
        raise requests.RequestException("upstream unavailable")

    monkeypatch.setattr(
        "src.services.ics_combiner.requests.get",
        raise_request_exception,
    )

    ics_text, is_stale = combiner.fetch_source_ics(source)

    assert ics_text == VALID_ICS
    assert is_stale is True
    assert (f"{cache_key}:lkg", VALID_ICS, None) in backend.set_calls
    assert (cache_key, "", CacheTTL.ICS_SOURCE_FAILURE_BACKOFF) in backend.set_calls


def test_fetch_failure_migrates_legacy_last_known_good_cache(
    monkeypatch, cache, backend
):
    monkeypatch.setattr(CacheTTL, "ICS_SOURCE_LKG", None)
    source = {"Id": 1, "Url": "https://example.com/calendar.ics"}
    combiner = ICSCombiner(cache=cache, cache_namespace="family")
    cache_key = combiner._cache_key_for_source(source)
    legacy_cache_key = combiner._legacy_cache_key_for_source(source)
    backend.seed(f"{legacy_cache_key}:lkg", VALID_ICS)

    def raise_request_exception(*_args, **_kwargs):
        raise requests.RequestException("upstream unavailable")

    monkeypatch.setattr(
        "src.services.ics_combiner.requests.get",
        raise_request_exception,
    )

    ics_text, is_stale = combiner.fetch_source_ics(source)

    assert ics_text == VALID_ICS
    assert is_stale is True
    assert (cache_key, "", CacheTTL.ICS_SOURCE_FAILURE_BACKOFF) in backend.set_calls
    assert (f"{cache_key}:lkg", VALID_ICS, None) in backend.set_calls


def test_combine_prunes_removed_source_cache_for_current_namespace(
    monkeypatch, cache, backend
):
    monkeypatch.setattr(CacheTTL, "ICS_SOURCE_LKG", None)
    combiner = ICSCombiner(cache=cache, cache_namespace="family")
    active = {"Id": 1, "Url": "https://example.com/active.ics"}
    removed = {"Id": 2, "Url": "https://example.com/removed.ics"}
    active_key = combiner._cache_key_for_source(active)
    removed_key = combiner._cache_key_for_source(removed)
    other_app_key = "ics:other:source:2:abc"
    backend.seed(combiner._source_index_key(), [active_key, removed_key])
    backend.seed(removed_key, VALID_ICS)
    backend.seed(f"{removed_key}:lkg", VALID_ICS)
    backend.seed(other_app_key, VALID_ICS)

    def fake_fetch(source):
        parsed = ICSCombiner._parse_ics_text(VALID_ICS)
        return VALID_ICS, False, parsed

    combiner._fetch_source_ics = fake_fetch

    combined = combiner.combine([active], "Combined", days_history=0)

    assert b"SUMMARY:Cached event" in combined
    assert cache.get(removed_key) is None
    assert cache.get(f"{removed_key}:lkg") is None
    assert cache.get(combiner._source_index_key()) == [active_key]
    assert cache.get(other_app_key) == VALID_ICS


def test_zero_refresh_seconds_still_backs_off_failures(monkeypatch, cache, backend):
    source = {
        "Id": 1,
        "Url": "https://example.com/calendar.ics",
        "RefreshSeconds": 0,
    }
    combiner = ICSCombiner(cache=cache)
    cache_key = combiner._cache_key_for_source(source)
    backend.seed(f"{cache_key}:lkg", VALID_ICS)

    def raise_request_exception(*_args, **_kwargs):
        raise requests.RequestException("upstream unavailable")

    monkeypatch.setattr(
        "src.services.ics_combiner.requests.get",
        raise_request_exception,
    )

    ics_text, is_stale = combiner.fetch_source_ics(source)

    assert ics_text == VALID_ICS
    assert is_stale is True
    assert (cache_key, "", CacheTTL.ICS_SOURCE_FAILURE_BACKOFF) in backend.set_calls
    assert cache.get(cache_key) == ""


def test_negative_cache_hit_skips_network_and_serves_last_known_good(
    monkeypatch, cache, backend
):
    monkeypatch.setattr(CacheTTL, "ICS_SOURCE_LKG", None)
    source = {"Id": 1, "Url": "https://example.com/calendar.ics"}
    combiner = ICSCombiner(cache=cache)
    cache_key = combiner._cache_key_for_source(source)
    backend.seed(cache_key, "")
    backend.seed(f"{cache_key}:lkg", VALID_ICS)

    def fail_get(*_args, **_kwargs):
        raise AssertionError("network should not be called on negative cache hit")

    monkeypatch.setattr("src.services.ics_combiner.requests.get", fail_get)

    ics_text, is_stale = combiner.fetch_source_ics(source)

    assert ics_text == VALID_ICS
    assert is_stale is True


def test_lkg_cache_hit_does_not_renormalize(monkeypatch, cache, backend):
    source = {"Id": 1, "Url": "https://example.com/calendar.ics"}
    combiner = ICSCombiner(cache=cache)
    cache_key = combiner._cache_key_for_source(source)
    backend.seed(cache_key, "")
    backend.seed(f"{cache_key}:lkg", VALID_ICS)

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


def test_invalid_http_200_does_not_replace_last_known_good_cache(
    monkeypatch, cache, backend
):
    source = {
        "Id": 1,
        "Url": "https://example.com/calendar.ics",
        "RefreshSeconds": 88,
    }
    combiner = ICSCombiner(cache=cache)
    cache_key = combiner._cache_key_for_source(source)
    lkg_key = f"{cache_key}:lkg"
    backend.seed(lkg_key, VALID_ICS)

    monkeypatch.setattr(
        "src.services.ics_combiner.requests.get",
        lambda *_args, **_kwargs: FakeResponse(INVALID_ICS),
    )

    ics_text, is_stale = combiner.fetch_source_ics(source)

    assert ics_text == VALID_ICS
    assert is_stale is True
    assert (cache_key, "", CacheTTL.ICS_SOURCE_FAILURE_BACKOFF) in backend.set_calls
    assert cache.get(lkg_key) == VALID_ICS


def test_invalid_primary_cache_entry_is_deleted_and_refetched(
    monkeypatch, cache, backend
):
    source = {"Id": 1, "Url": "https://example.com/calendar.ics"}
    combiner = ICSCombiner(cache=cache)
    cache_key = combiner._cache_key_for_source(source)
    backend.seed(cache_key, INVALID_ICS)
    calls = []

    def get(url, timeout, **kwargs):
        calls.append((url, timeout))
        return FakeResponse(VALID_ICS_UPDATED)

    monkeypatch.setattr("src.services.ics_combiner.requests.get", get)

    ics_text, is_stale = combiner.fetch_source_ics(source)

    assert ics_text == VALID_ICS_UPDATED
    assert is_stale is False
    assert backend.deleted == [cache_key]
    assert calls == [(source["Url"], 15)]


@pytest.mark.parametrize(
    "status_code, retry_after, expected_ttl",
    [
        # Non-429 failure with no Retry-After falls back to plain backoff.
        (500, None, CacheTTL.ICS_SOURCE_FAILURE_BACKOFF),
        # Retry-After in seconds is honored verbatim.
        (429, "1800", 1800),
        # Retry-After larger than the 24h cap is clamped.
        (429, "999999", 86400),
        # HTTP 429 without Retry-After uses the rate-limit backoff.
        (429, None, CacheTTL.ICS_SOURCE_RATE_LIMIT_BACKOFF),
        # Unparseable (HTTP-date) Retry-After falls back to rate-limit backoff.
        (
            429,
            "Wed, 21 Oct 2026 07:28:00 GMT",
            CacheTTL.ICS_SOURCE_RATE_LIMIT_BACKOFF,
        ),
    ],
)
def test_fetch_failure_negative_cache_ttl_honors_retry_after_and_429(
    monkeypatch, status_code, retry_after, expected_ttl, cache, backend
):
    source = {"Id": 1, "Url": "https://example.com/calendar.ics"}
    combiner = ICSCombiner(cache=cache)
    cache_key = combiner._cache_key_for_source(source)

    headers = {"Retry-After": retry_after} if retry_after is not None else {}

    monkeypatch.setattr(
        "src.services.ics_combiner.requests.get",
        lambda *_args, **_kwargs: FakeResponse(
            status_code=status_code, headers=headers
        ),
    )

    combiner.fetch_source_ics(source)

    assert (cache_key, "", expected_ttl) in backend.set_calls


def test_fetch_sends_identifying_user_agent_header(monkeypatch):
    captured = {}
    source = {"Id": 1, "Url": "https://example.com/calendar.ics"}
    combiner = ICSCombiner(cache=None)

    def capture_get(*_args, **kwargs):
        captured.update(kwargs)
        return FakeResponse(VALID_ICS)

    monkeypatch.setattr("src.services.ics_combiner.requests.get", capture_get)

    combiner.fetch_source_ics(source)

    assert captured["headers"]["User-Agent"] == (
        "ics-combiner/1.0 (+https://github.com/amattas/ics-combiner)"
    )

import os
import re
import json
import uuid
import hashlib
import logging
import requests
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime, date, timedelta
from zoneinfo import ZoneInfo
from icalendar import Calendar, Event

from .cache import RedisCache, CacheTTL

logger = logging.getLogger(__name__)

SourceFetchResult = Tuple[Optional[str], bool, Optional[Calendar]]

MAX_ICS_RESPONSE_BYTES = 10 * 1024 * 1024  # 10 MB


_GUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)


class ICSCombiner:
    def __init__(self, cache: Optional[RedisCache] = None):
        self.cache = cache

    @staticmethod
    def _create_uid(input_string: str) -> str:
        guid = uuid.uuid5(uuid.NAMESPACE_DNS, input_string)
        return str(guid)

    @staticmethod
    def _today_utc_date() -> date:
        return datetime.now(ZoneInfo("UTC")).date()

    @staticmethod
    def _normalize_ics_text(ics_text: str) -> str:
        """
        Normalize a few common non‑RFC5545 datetime forms that appear in some
        source feeds so that icalendar can parse them.

        Example fixed pattern:
          DTSTART:2025-11-01 13:30:00+00:00  ->  DTSTART:20251101T133000Z
        """

        def _replace(match: re.Match) -> str:
            prop = match.group(1)  # DTSTART or DTEND
            raw_value = match.group(2).strip()
            try:
                dt = datetime.fromisoformat(raw_value)
            except ValueError:
                # If we cannot parse, leave the line unchanged
                return match.group(0)

            if not isinstance(dt, datetime):
                return match.group(0)

            # Convert offset-aware times to UTC and emit Z suffix
            if dt.tzinfo is not None:
                dt = dt.astimezone(ZoneInfo("UTC"))
                formatted = dt.strftime("%Y%m%dT%H%M%SZ")
            else:
                formatted = dt.strftime("%Y%m%dT%H%M%S")

            return f"{prop}:{formatted}"

        pattern = re.compile(
            r"^(DTSTART|DTEND):(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[+-]\d{2}:\d{2})?)\s*$",
            re.MULTILINE,
        )
        return pattern.sub(_replace, ics_text)

    @staticmethod
    def _parse_datetime_or_date(value: str) -> Optional[object]:
        """
        Best-effort parsing for non‑RFC5545 datetime/date strings that appear in
        some tolerant ICS feeds (for example: '2025-11-01 13:30:00+00:00').

        Returns a datetime or date if parsing succeeds, otherwise None.
        """
        text = value.strip()
        if not text:
            return None

        # Try full ISO 8601 datetime first (with or without offset, with space or 'T')
        try:
            return datetime.fromisoformat(text)
        except ValueError:
            pass

        # Try ISO date (YYYY-MM-DD)
        try:
            return date.fromisoformat(text)
        except ValueError:
            return None

    @staticmethod
    def _validate_sources(calendars: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen_ids: set[int] = set()
        validated = []
        for i, cal in enumerate(calendars):
            raw_id = cal.get("Id")
            if raw_id is None:
                raise ValueError(f"Source at index {i} is missing required 'Id' field")
            try:
                cal["Id"] = int(raw_id)
            except (TypeError, ValueError) as err:
                raise ValueError(
                    f"Source at index {i} has non-integer Id: {raw_id!r}"
                ) from err
            if cal["Id"] in seen_ids:
                raise ValueError(f"Duplicate source Id: {cal['Id']}")
            seen_ids.add(cal["Id"])

            if not cal.get("Url"):
                raise ValueError(f"Source {cal['Id']} is missing required 'Url' field")

            if cal.get("Url", "").startswith("http://"):
                logger.warning(
                    "Source %s uses insecure HTTP URL — consider switching to HTTPS",
                    cal["Id"],
                )

            for field in ("Duration", "PadStartMinutes"):
                val = cal.get(field)
                if val is not None:
                    if not isinstance(val, (int, float)):
                        raise ValueError(
                            f"Source {cal['Id']} has non-numeric {field}: {val!r}"
                        )
                    if val < 0:
                        raise ValueError(
                            f"Source {cal['Id']} has negative {field}: {val}"
                        )
                    cal[field] = int(val)

            validated.append(cal)
        return validated

    @staticmethod
    def load_sources_from_env() -> Tuple[List[Dict[str, Any]], str, int]:
        sources_raw = os.getenv("ICS_SOURCES") or os.getenv("CalendarSources")
        if not sources_raw:
            raise ValueError("ICS_SOURCES (or CalendarSources) env var is required")

        try:
            calendars = json.loads(sources_raw)
        except Exception as err:
            raise ValueError("ICS_SOURCES is not valid JSON") from err

        calendars = ICSCombiner._validate_sources(calendars)

        name = os.getenv("ICS_NAME") or os.getenv("CalendarName") or "Combined Calendar"
        days_history = int(
            os.getenv("ICS_DAYS_HISTORY") or os.getenv("CalendarDaysHistory") or 0
        )
        return calendars, name, days_history

    def _get_source_ttl(self, source: Dict[str, Any]) -> int:
        # Source-level override from source configuration JSON
        if isinstance(source.get("RefreshSeconds"), int):
            return max(0, int(source["RefreshSeconds"]))

        # Global default (can be overridden via CACHE_TTL_ICS_SOURCE_DEFAULT)
        return CacheTTL.ICS_SOURCE_DEFAULT

    def _cache_key_for_source(self, source: Dict[str, Any]) -> str:
        sid = source.get("Id", "unknown")
        url = source.get("Url", "")
        # Use SHA-256 for cache key derivation to avoid weak-hash warnings
        url_hash = hashlib.sha256(url.encode("utf-8")).hexdigest() if url else "no_url"
        return f"ics:source:{sid}:{url_hash}"

    @staticmethod
    def _parse_ics_text(ics_text: str) -> Optional[Calendar]:
        if "BEGIN:VCALENDAR" not in ics_text.upper():
            return None

        try:
            return Calendar.from_ical(ics_text)
        except Exception:
            return None

    def _fetch_source_ics(self, source: Dict[str, Any]) -> SourceFetchResult:
        """Fetch and parse a single ICS source, using Redis cache if available.

        Returns (ics_text, is_stale, parsed_calendar) where is_stale indicates
        the data came from a last-known-good fallback after a fetch failure.
        """
        if not source.get("Url"):
            logger.warning("Source missing Url: %s", source)
            return None, False, None

        cache_key = self._cache_key_for_source(source)
        lkg_key = f"{cache_key}:lkg"
        ttl = self._get_source_ttl(source)
        failure_backoff_ttl = CacheTTL.ICS_SOURCE_FAILURE_BACKOFF

        def get_lkg_from_cache() -> SourceFetchResult:
            if not self.cache or not self.cache.is_connected():
                return None, False, None

            lkg = self.cache.get(lkg_key)
            if isinstance(lkg, str) and lkg:
                parsed_lkg = self._parse_ics_text(lkg)
                if parsed_lkg is not None:
                    logger.info(
                        "Using last-known-good cache for source %s", source.get("Id")
                    )
                    return lkg, True, parsed_lkg

                logger.warning(
                    "Ignoring invalid last-known-good cache for source %s",
                    source.get("Id"),
                )
                self.cache.delete(lkg_key)

            return None, False, None

        def record_failure_and_get_lkg() -> SourceFetchResult:
            if self.cache and self.cache.is_connected():
                # Keep failure backoff separate from the source freshness TTL so
                # no-cache sources do not retry a failing upstream on every request.
                self.cache.set(cache_key, "", ttl=failure_backoff_ttl)
                return get_lkg_from_cache()

            return None, False, None

        # Try cache (empty string = negative cache from a prior failure)
        if self.cache and self.cache.is_connected():
            cached = self.cache.get(cache_key)
            if isinstance(cached, str):
                if not cached:
                    # Negative cache hit — don't retry upstream, serve LKG if available
                    return get_lkg_from_cache()

                parsed_cached = self._parse_ics_text(cached)
                if parsed_cached is not None:
                    return cached, False, parsed_cached

                logger.warning(
                    "Ignoring invalid cached ICS for source %s", source.get("Id")
                )
                self.cache.delete(cache_key)

        # Fetch from network
        try:
            resp = requests.get(source["Url"], timeout=15, stream=True)
            resp.raise_for_status()
            chunks = []
            downloaded = 0
            for chunk in resp.iter_content(chunk_size=8192, decode_unicode=False):
                downloaded += len(chunk)
                if downloaded > MAX_ICS_RESPONSE_BYTES:
                    logger.error(
                        "Response too large for source %s (>%s bytes), aborting",
                        source.get("Id"),
                        MAX_ICS_RESPONSE_BYTES,
                    )
                    resp.close()
                    return record_failure_and_get_lkg()
                chunks.append(chunk)
            raw_text = b"".join(chunks).decode("utf-8", errors="replace")
        except requests.RequestException as err:
            logger.error("Failed to fetch ICS for source %s: %s", source.get("Id"), err)
            return record_failure_and_get_lkg()

        ics_text = self._normalize_ics_text(raw_text)
        parsed_ics = self._parse_ics_text(ics_text)
        if parsed_ics is None:
            logger.error("Fetched invalid ICS for source %s", source.get("Id"))
            return record_failure_and_get_lkg()

        # Store in cache
        if self.cache and self.cache.is_connected():
            # Primary cache (controls fetch frequency)
            self.cache.set(cache_key, ics_text, ttl=ttl)
            # Last-known-good cache (long-lived fallback)
            self.cache.set(lkg_key, ics_text, ttl=CacheTTL.ICS_SOURCE_LKG)

        return ics_text, False, parsed_ics

    def fetch_source_ics(self, source: Dict[str, Any]) -> Tuple[Optional[str], bool]:
        """Fetch a single ICS source, using Redis cache if available.

        Returns (ics_text, is_stale) where is_stale indicates the data came
        from a last-known-good fallback after a fetch failure.
        """
        ics_text, is_stale, _parsed_calendar = self._fetch_source_ics(source)
        return ics_text, is_stale

    def combine(
        self,
        calendars: List[Dict[str, Any]],
        name: str,
        days_history: int,
        show: Optional[List[int]] = None,
        hide: Optional[List[int]] = None,
    ) -> bytes:
        today = self._today_utc_date()

        combined_cal = Calendar()
        combined_cal.add("prodid", "-//ICS Combiner//NONSGML//EN")
        combined_cal.add("version", "2.0")
        combined_cal.add("x-wr-calname", name)

        temp_cal: Dict[str, Event] = {}
        seen_tz: set[str] = set()

        def should_include(cal: Dict[str, Any]) -> bool:
            cid = cal.get("Id")
            if show is not None and cid not in show:
                return False
            if hide is not None and cid in hide:
                return False
            return True

        for calendar in calendars:
            if calendar.get("Id") is None:
                raise ValueError("Invalid calendar source configuration (missing Id)")

            if not should_include(calendar):
                continue

            ics_text, is_stale, ical = self._fetch_source_ics(calendar)
            if not ics_text or ical is None:
                # Skip failed sources
                continue

            # Copy timezone definitions, deduplicating identical ones
            for tz in ical.walk("VTIMEZONE"):
                tzid = str(tz.get("TZID", ""))
                tz_serialized = tz.to_ical()
                tz_key = f"{tzid}:{tz_serialized}"
                if tz_key not in seen_tz:
                    seen_tz.add(tz_key)
                    combined_cal.add_component(tz)

            for component in ical.walk("VEVENT"):
                try:
                    end = component.get("dtend")

                    # Only show configured historical events
                    if end and days_history:
                        dt_val = end.dt
                        event_date = (
                            dt_val.date() if isinstance(dt_val, datetime) else dt_val
                        )
                        if (
                            event_date < today - timedelta(days=days_history)
                            and "RRULE" not in component
                        ):
                            continue

                    copied_event = Event()
                    for key, value in component.items():
                        if isinstance(value, list):
                            for item in value:
                                copied_event.add(key, item)
                        else:
                            copied_event.add(key, value)

                    # Generate a fallback UID if missing
                    if copied_event.get("UID") is None:
                        fallback_uid = self._create_uid(
                            f"{calendar.get('Id')}-{copied_event.get('DTSTART')}-{copied_event.get('SUMMARY')}"
                        )
                        copied_event.add("uid", fallback_uid)
                        logger.warning(
                            "Generated fallback UID for event without UID (source_id=%s, summary=%s)",
                            calendar.get("Id"),
                            copied_event.get("SUMMARY"),
                        )

                    # Resolve and normalize DTSTART (may be missing or stored as text)
                    dtstart_prop = copied_event.get("DTSTART")
                    if dtstart_prop is None:
                        logger.warning(
                            "Skipping event without DTSTART (source_id=%s, prefix=%s, summary=%s)",
                            calendar.get("Id"),
                            calendar.get("Prefix"),
                            copied_event.get("SUMMARY"),
                        )
                        # Skip events without a start time
                        continue

                    # icalendar properties usually carry the real value on .dt
                    dtstart_val = getattr(dtstart_prop, "dt", dtstart_prop)

                    # Some feeds provide non‑RFC5545 strings that icalendar cannot
                    # interpret as dates/times (for example, ISO 8601 with spaces
                    # and offsets). Normalize those into proper datetime/date values
                    # so that to_ical() always emits RFC5545-compliant DTSTART.
                    if isinstance(dtstart_val, str):
                        parsed = self._parse_datetime_or_date(dtstart_val)
                        if parsed is None:
                            logger.warning(
                                "Skipping event with unparseable DTSTART (source_id=%s, prefix=%s, raw_dtstart=%s, summary=%s)",
                                calendar.get("Id"),
                                calendar.get("Prefix"),
                                dtstart_val,
                                copied_event.get("SUMMARY"),
                            )
                            continue
                        dtstart_val = parsed
                        # Replace existing DTSTART with a proper datetime- or date-valued one
                        copied_event.pop("DTSTART", None)
                        copied_event.add("dtstart", dtstart_val)

                    # At this point dtstart_val should be a datetime or date. If not, skip.
                    if not isinstance(dtstart_val, (datetime, date)):
                        logger.warning(
                            "Skipping event with invalid DTSTART type (source_id=%s, prefix=%s, type=%s, summary=%s)",
                            calendar.get("Id"),
                            calendar.get("Prefix"),
                            type(dtstart_val),
                            copied_event.get("SUMMARY"),
                        )
                        continue

                    # Set duration if specified (combcal semantics) – for timed events only.
                    if calendar.get("Duration") is not None and isinstance(
                        dtstart_val, datetime
                    ):
                        # Override any existing duration and remove DTEND so that the
                        # effective length is driven exclusively by DURATION, matching
                        # the original combcal behaviour and what icalendar >= 6 emits.
                        copied_event.pop("DURATION", None)
                        copied_event.pop("DTEND", None)
                        copied_event.add(
                            "DURATION", timedelta(minutes=calendar.get("Duration"))
                        )
                    else:
                        has_dtend = copied_event.get("DTEND") is not None
                        has_duration = copied_event.get("DURATION") is not None

                        # If there is no duration or end time, add sensible defaults
                        # (5 minutes for timed events, 1 day for all‑day events).
                        if not has_dtend and not has_duration:
                            if isinstance(dtstart_val, datetime):
                                copied_event.add("DURATION", timedelta(minutes=5))
                            elif isinstance(dtstart_val, date):
                                copied_event.add("DURATION", timedelta(days=1))
                            else:
                                # Should not occur given the type check above, but keep guard.
                                continue

                    # Add padding (arrival time) using the original combcal rules,
                    # but in a way that works across icalendar versions:
                    # - Shift DTSTART earlier by PadStartMinutes.
                    # - Set DURATION based on the event's effective duration plus the pad.
                    pad_minutes = calendar.get("PadStartMinutes")
                    if pad_minutes is not None and isinstance(dtstart_val, datetime):
                        pad = timedelta(minutes=pad_minutes)

                        # Compute original duration. If the event already had a
                        # DURATION, use that. Otherwise derive it from DTEND and the
                        # *original* DTSTART.
                        dur_prop = copied_event.get("DURATION")
                        dtend_prop = copied_event.get("DTEND")

                        original_duration: Optional[timedelta] = None
                        if dur_prop is not None:
                            try:
                                original_duration = copied_event.decoded("DURATION")
                            except Exception:
                                val = getattr(dur_prop, "dt", None)
                                if isinstance(val, timedelta):
                                    original_duration = val
                        elif dtend_prop is not None:
                            dtend_val = getattr(dtend_prop, "dt", dtend_prop)
                            if isinstance(dtend_val, datetime):
                                original_duration = dtend_val - dtstart_val

                        if original_duration is not None:
                            # Shift start earlier by the pad.
                            new_start = dtstart_val - pad
                            copied_event.pop("DTSTART", None)
                            copied_event.add("DTSTART", new_start)

                            # Match combcal's duration semantics:
                            # - If the event *only* had DURATION originally, the new
                            #   total duration is original_duration + pad.
                            # - If it had an explicit DTEND (no DURATION), its
                            #   combcal behaviour is: duration becomes
                            #   (original_duration + pad) and then another pad is
                            #   added, i.e. original_duration + 2*pad.
                            if dur_prop is not None:
                                new_duration = original_duration + pad
                            elif dtend_prop is not None:
                                new_duration = original_duration + (pad * 2)
                            else:
                                new_duration = original_duration

                            # Use DURATION exclusively to represent the new length.
                            copied_event.pop("DURATION", None)
                            copied_event.pop("DTEND", None)
                            copied_event.add("DURATION", new_duration)

                    # Add stale indicator and prefix
                    stale_marker = "⚠️ " if is_stale else ""
                    if calendar.get("Prefix") is not None:
                        copied_event["SUMMARY"] = (
                            f"{stale_marker}{calendar.get('Prefix')}: {copied_event.get('SUMMARY')}"
                        )
                    elif is_stale:
                        copied_event["SUMMARY"] = (
                            f"{stale_marker}{copied_event.get('SUMMARY')}"
                        )

                    # Update UID to a unique value if specified
                    current_uid = str(copied_event.get("UID", ""))
                    if calendar.get("MakeUnique"):
                        new_uid = self._create_uid(
                            f"{calendar.get('Id')}-{current_uid}"
                        )
                        copied_event.pop("UID", None)
                        copied_event.add("uid", new_uid)
                    else:
                        if not _GUID_RE.match(current_uid):
                            new_uid = self._create_uid(current_uid)
                            copied_event.pop("UID", None)
                            copied_event.add("uid", new_uid)

                    # Remove Organizer
                    copied_event.pop("ORGANIZER", None)

                    # Remove empty lines from the description
                    if copied_event.get("DESCRIPTION"):
                        try:
                            desc_str = copied_event.decoded("DESCRIPTION").decode(
                                "utf-8", errors="ignore"
                            )
                        except Exception:
                            desc_str = str(copied_event.get("DESCRIPTION"))
                        desc_str = "\n".join(
                            line for line in desc_str.splitlines() if line.strip()
                        )
                        copied_event["DESCRIPTION"] = desc_str.strip()

                    # De-duplicate or add immediately
                    if calendar.get("FilterDuplicates"):
                        dedup_key = (
                            str(copied_event.get("UID", "")),
                            str(copied_event.get("RECURRENCE-ID", "")),
                        )
                        temp_cal[dedup_key] = copied_event
                    else:
                        combined_cal.add_component(copied_event)

                except Exception:
                    logger.exception(
                        "Error processing event in source %s, skipping",
                        calendar.get("Id"),
                    )

        # Add deduplicated events
        for e in temp_cal.values():
            combined_cal.add_component(e)

        return combined_cal.to_ical()

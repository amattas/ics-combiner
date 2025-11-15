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


class ICSCombiner:
    def __init__(self, cache: Optional[RedisCache] = None):
        self.cache = cache

    @staticmethod
    def _create_uid(input_string: str) -> str:
        # Use UUID5 (SHA-1 under the hood) without manual hashing to avoid direct weak-hash usage
        guid = uuid.uuid5(uuid.NAMESPACE_DNS, input_string)
        return str(guid)

    @staticmethod
    def _today_utc_date() -> date:
        return datetime.now(ZoneInfo("UTC")).date()

    @staticmethod
    def _guid_regex():
        return re.compile(
            r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
        )

    @staticmethod
    def load_sources_from_env() -> Tuple[List[Dict[str, Any]], str, int]:
        # Backward compatibility with Azure function env names
        sources_raw = os.getenv("ICS_SOURCES") or os.getenv("CalendarSources")
        if not sources_raw:
            raise ValueError("ICS_SOURCES (or CalendarSources) env var is required")

        try:
            calendars = json.loads(sources_raw)
        except Exception as err:
            raise ValueError("ICS_SOURCES is not valid JSON") from err

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

    def fetch_source_ics(self, source: Dict[str, Any]) -> Optional[str]:
        """Fetch a single ICS source, using Redis cache if available."""
        if not source.get("Url"):
            logger.warning(f"Source missing Url: {source}")
            return None

        cache_key = self._cache_key_for_source(source)
        ttl = self._get_source_ttl(source)

        # Try cache
        if self.cache and self.cache.is_connected():
            cached = self.cache.get(cache_key)
            if isinstance(cached, str):
                return cached

        # Fetch from network
        try:
            resp = requests.get(source["Url"], timeout=15)
            resp.raise_for_status()
        except requests.RequestException as err:
            logger.error(f"Failed to fetch ICS for source {source.get('Id')}: {err}")
            return None

        ics_text = resp.text

        # Store in cache
        if self.cache and self.cache.is_connected():
            # Store as raw string
            self.cache.set(cache_key, ics_text, ttl=ttl)

        return ics_text

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
        guid_re = self._guid_regex()

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

            ics_text = self.fetch_source_ics(calendar)
            if not ics_text:
                # Skip failed sources
                continue

            try:
                ical = Calendar.from_ical(ics_text)
            except Exception as err:
                logger.error(
                    f"Unable to parse calendar with id {calendar.get('Id')}: {err}"
                )
                continue

            # Copy timezone definitions to combined calendar
            for tz in ical.walk("VTIMEZONE"):
                combined_cal.add_component(tz)

            for component in ical.walk("VEVENT"):
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

                # Resolve DTSTART safely (may be missing or wrapped)
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

                # Set duration if specified
                if calendar.get("Duration") is not None and isinstance(
                    dtstart_val, datetime
                ):
                    copied_event.DURATION = timedelta(minutes=calendar.get("Duration"))
                else:
                    # Safely check for missing DTEND/DURATION without relying on attributes
                    has_dtend = copied_event.get("DTEND") is not None
                    has_duration = copied_event.get("DURATION") is not None

                    # If there is no duration or end time set appropriately
                    if not has_dtend and not has_duration:
                        if isinstance(dtstart_val, datetime):
                            copied_event.DURATION = timedelta(minutes=5)
                        elif isinstance(dtstart_val, date):
                            copied_event.DURATION = timedelta(days=1)
                        else:
                            # Skip if DTSTART is not recognisable
                            continue

                # Add padding
                if calendar.get("PadStartMinutes") is not None and isinstance(
                    dtstart_val, datetime
                ):
                    pad = timedelta(minutes=calendar.get("PadStartMinutes"))
                    # Shift start earlier and extend duration accordingly
                    new_start = dtstart_val - pad
                    copied_event["DTSTART"] = new_start
                    copied_event.DURATION = copied_event.duration + pad

                # Add prefix
                if calendar.get("Prefix") is not None:
                    copied_event["SUMMARY"] = (
                        f"{calendar.get('Prefix')}: {copied_event['SUMMARY']}"
                    )

                # Update UID to a unique value if specified
                if calendar.get("MakeUnique") is not None and calendar.get(
                    "MakeUnique"
                ):
                    copied_event["UID"] = self._create_uid(
                        f"{calendar.get('Id')}-{copied_event['UID']}"
                    )
                else:
                    # Ensure UID is a GUID for Outlook compatibility
                    if not guid_re.match(copied_event["UID"]):
                        copied_event["UID"] = self._create_uid(f"{copied_event['UID']}")

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
                if calendar.get("FilterDuplicates") is not None and calendar.get(
                    "FilterDuplicates"
                ):
                    temp_cal[copied_event["UID"]] = copied_event
                else:
                    combined_cal.add_component(copied_event)

        # Add deduplicated events
        for e in temp_cal.values():
            combined_cal.add_component(e)

        return combined_cal.to_ical()

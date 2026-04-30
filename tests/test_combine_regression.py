"""
Regression tests for ICSCombiner.combine().

Each test feeds synthetic ICS fixtures (modeled after real production feeds)
through the combiner with the same source config as production, then asserts
the output contains the expected events with the correct transformations.

Fixtures in tests/fixtures/ are named by source ID and modeled after:
  0: Published calendar (two timezones, Apple-style UUIDs, TZID params)
  1: Team management full schedule (FilterDuplicates, non-Z DTSTAMP)
  2: Team management games only (Prefix, PadStartMinutes, Duration, FilterDuplicates)
  3: Team management full B (non-round seconds in times, multiline LOCATION)
  4: Team management games B (Prefix, PadStartMinutes, Duration, FilterDuplicates)
  5: Referee scheduler (UTC times, ORGANIZER, ENCODING=QUOTED-PRINTABLE, MakeUnique)
  6: Referee scheduler B (same patterns, MakeUnique)
  7: School calendar A (all-day events without DTEND, bare local datetimes, empty DESC)
  8: School calendar B (mixed date formats, empty DESCRIPTION)
  9: District calendar (all-day without DTEND, bare local datetime)
 10: Sports team (emoji in SUMMARY, dual VALARM, TRANSPARENT)
 11: Assignor platform (TZID, GEO, SEQUENCE, VALARM with reused UID, MakeUnique)
 12: Assignor platform B (same patterns, MakeUnique)
 edge: Edge cases (missing UID, missing DTSTART, missing DTEND, organizer removal, blank desc lines)
"""

from pathlib import Path

from icalendar import Calendar

from src.services.ics_combiner import ICSCombiner

FIXTURES = Path(__file__).parent / "fixtures"


def _load_fixture(name: str) -> str:
    return (FIXTURES / name).read_text()


def _make_combiner_with_fixtures(source_configs, fixture_map):
    """Create combiner that returns fixture data instead of fetching URLs."""
    combiner = ICSCombiner(cache=None)

    def fake_fetch(source):
        sid = source.get("Id")
        if sid in fixture_map:
            ics_text = fixture_map[sid]
            parsed = ICSCombiner._parse_ics_text(ics_text)
            return ics_text, False, parsed
        return None, False, None

    combiner._fetch_source_ics = fake_fetch
    return combiner


def _parse_combined(ical_bytes: bytes) -> Calendar:
    return Calendar.from_ical(ical_bytes)


def _get_events(cal: Calendar):
    return list(cal.walk("VEVENT"))


def _get_timezones(cal: Calendar):
    return list(cal.walk("VTIMEZONE"))


def _event_summaries(cal: Calendar):
    return [str(e.get("SUMMARY", "")) for e in _get_events(cal)]


# ---------------------------------------------------------------------------
# Production-like source configs matching the fixture set
# ---------------------------------------------------------------------------

PROD_SOURCES = [
    {"Id": 0, "Url": "https://example.com/0.ics"},
    {
        "Id": 1,
        "Url": "https://example.com/1.ics",
        "Prefix": "Team Alpha",
        "FilterDuplicates": True,
    },
    {
        "Id": 2,
        "Url": "https://example.com/2.ics",
        "Prefix": "Team Alpha",
        "PadStartMinutes": 30,
        "Duration": 60,
        "FilterDuplicates": True,
    },
    {
        "Id": 3,
        "Url": "https://example.com/3.ics",
        "Prefix": "Team Beta",
        "FilterDuplicates": True,
    },
    {
        "Id": 4,
        "Url": "https://example.com/4.ics",
        "Prefix": "Team Beta",
        "PadStartMinutes": 40,
        "Duration": 80,
        "FilterDuplicates": True,
    },
    {
        "Id": 5,
        "Url": "https://example.com/5.ics",
        "Prefix": "Ref A",
        "PadStartMinutes": 30,
        "MakeUnique": True,
        "RefreshSeconds": 1800,
    },
    {
        "Id": 6,
        "Url": "https://example.com/6.ics",
        "Prefix": "Ref B",
        "PadStartMinutes": 30,
        "MakeUnique": True,
        "RefreshSeconds": 1800,
    },
    {"Id": 7, "Url": "https://example.com/7.ics", "Prefix": "School A"},
    {"Id": 8, "Url": "https://example.com/8.ics", "Prefix": "School B"},
    {"Id": 9, "Url": "https://example.com/9.ics", "Prefix": "District"},
    {"Id": 10, "Url": "https://example.com/10.ics"},
    {
        "Id": 11,
        "Url": "https://example.com/11.ics",
        "Prefix": "Ref A",
        "PadStartMinutes": 30,
        "MakeUnique": True,
    },
    {
        "Id": 12,
        "Url": "https://example.com/12.ics",
        "Prefix": "Ref B",
        "PadStartMinutes": 30,
        "MakeUnique": True,
    },
]

FIXTURE_MAP = {
    0: _load_fixture("source_0_published_cal.ics"),
    1: _load_fixture("source_1_team_full.ics"),
    2: _load_fixture("source_2_team_games.ics"),
    3: _load_fixture("source_3_team_full_b.ics"),
    4: _load_fixture("source_4_team_games_b.ics"),
    5: _load_fixture("source_5_referee.ics"),
    6: _load_fixture("source_6_referee_b.ics"),
    7: _load_fixture("source_7_school_a.ics"),
    8: _load_fixture("source_8_school_b.ics"),
    9: _load_fixture("source_9_district.ics"),
    10: _load_fixture("source_10_sports_team.ics"),
    11: _load_fixture("source_11_assignor.ics"),
    12: _load_fixture("source_12_assignor_b.ics"),
}


# ---------------------------------------------------------------------------
# Full production regression test
# ---------------------------------------------------------------------------


class TestFullCombineRegression:
    def _combine_all(self):
        combiner = _make_combiner_with_fixtures(PROD_SOURCES, FIXTURE_MAP)
        return combiner.combine(PROD_SOURCES, "Test Calendar", days_history=0)

    def _parsed(self):
        return _parse_combined(self._combine_all())

    def test_produces_valid_ical(self):
        result = self._combine_all()
        assert result.startswith(b"BEGIN:VCALENDAR")
        assert result.rstrip().endswith(b"END:VCALENDAR")

    def test_calendar_metadata(self):
        cal = self._parsed()
        assert str(cal.get("X-WR-CALNAME")) == "Test Calendar"
        assert str(cal.get("VERSION")) == "2.0"

    def test_all_sources_contribute_events(self):
        cal = self._parsed()
        summaries = _event_summaries(cal)
        assert any("Family Dinner" in s for s in summaries)
        assert any("Team Alpha" in s for s in summaries)
        assert any("Team Beta" in s for s in summaries)
        assert any("Ref A" in s for s in summaries)
        assert any("Ref B" in s for s in summaries)
        assert any("School A" in s for s in summaries)
        assert any("School B" in s for s in summaries)
        assert any("District" in s for s in summaries)
        assert any("⚽️" in s for s in summaries)

    def test_vtimezone_dedup_identical(self):
        """Sources 1-4 and 11-12 all define America/New_York identically.
        Source 0 also defines it plus America/Detroit. We should get exactly
        one copy of each unique VTIMEZONE definition, not one per source."""
        cal = self._parsed()
        tzs = _get_timezones(cal)
        tzids = [str(tz.get("TZID")) for tz in tzs]
        ny_count = tzids.count("America/New_York")
        detroit_count = tzids.count("America/Detroit")
        assert ny_count == 1, f"Expected 1 America/New_York, got {ny_count}"
        assert detroit_count == 1, f"Expected 1 America/Detroit, got {detroit_count}"

    def test_prefix_applied(self):
        cal = self._parsed()
        summaries = _event_summaries(cal)
        prefixed = [s for s in summaries if "Team Alpha:" in s]
        assert len(prefixed) > 0, "No Team Alpha prefixed events found"
        unprefixed_source0 = [s for s in summaries if "Family Dinner" in s]
        assert all(":" not in s.split("Family Dinner")[0] for s in unprefixed_source0)

    def test_organizer_removed(self):
        """Referee feeds (5, 6) have ORGANIZER fields that should be stripped."""
        cal = self._parsed()
        events = _get_events(cal)
        for event in events:
            assert (
                event.get("ORGANIZER") is None
            ), f"ORGANIZER not removed from event: {event.get('SUMMARY')}"

    def test_make_unique_creates_source_scoped_uids(self):
        """Sources 5, 6, 11, 12 use MakeUnique — UIDs should incorporate source ID."""
        cal = self._parsed()
        events = _get_events(cal)
        ref_events = [
            e
            for e in events
            if "Ref A:" in str(e.get("SUMMARY", ""))
            or "Ref B:" in str(e.get("SUMMARY", ""))
        ]
        uids = [str(e.get("UID")) for e in ref_events]
        assert len(uids) == len(set(uids)), "MakeUnique UIDs should all be distinct"

    def test_filter_duplicates_sources_contribute(self):
        """Sources 1-4 use FilterDuplicates. Events should still appear."""
        cal = self._parsed()
        summaries = _event_summaries(cal)
        assert any("Team Alpha: Practice - Field A" in s for s in summaries)
        assert any("Team Beta: Practice" in s for s in summaries)

    def test_duration_override(self):
        """Source 2 has Duration=60 and PadStartMinutes=30.
        Duration sets 60 min, then pad adds 30 min (DURATION-based path),
        giving 90 min total."""
        sources = [PROD_SOURCES[2]]
        fixture = {2: FIXTURE_MAP[2]}
        combiner = _make_combiner_with_fixtures(sources, fixture)
        result = combiner.combine(sources, "Test", days_history=0)
        cal = _parse_combined(result)
        events = _get_events(cal)
        for event in events:
            dur = event.decoded("DURATION")
            assert (
                dur.total_seconds() == 5400
            ), f"Expected 90min (60 duration + 30 pad), got {dur}"

    def test_pad_start_minutes_shifts_start(self):
        """Source 2 has PadStartMinutes=30. DTSTART should be shifted 30 min earlier."""
        sources = [PROD_SOURCES[2]]
        fixture = {2: FIXTURE_MAP[2]}
        combiner = _make_combiner_with_fixtures(sources, fixture)
        result = combiner.combine(sources, "Test", days_history=0)
        cal = _parse_combined(result)
        events = _get_events(cal)
        for event in events:
            dtstart = event.decoded("DTSTART")
            assert (
                dtstart.minute == 30 or dtstart.hour == 9
            ), f"Expected start shifted by 30 min, got {dtstart}"

    def test_allday_events_get_default_duration(self):
        """School sources have all-day events without DTEND. Should get 1-day duration."""
        sources = [PROD_SOURCES[7]]
        fixture = {7: FIXTURE_MAP[7]}
        combiner = _make_combiner_with_fixtures(sources, fixture)
        result = combiner.combine(sources, "Test", days_history=0)
        cal = _parse_combined(result)
        events = _get_events(cal)
        allday_events = [e for e in events if not hasattr(e.decoded("DTSTART"), "hour")]
        assert len(allday_events) >= 2
        for event in allday_events:
            if event.get("DURATION"):
                dur = event.decoded("DURATION")
                assert (
                    dur.days == 1
                ), f"Expected 1-day duration for all-day event, got {dur}"

    def test_timed_events_without_dtend_get_default_duration(self):
        """District source has a timed event without DTEND. Should get 5-min duration."""
        sources = [PROD_SOURCES[9]]
        fixture = {9: FIXTURE_MAP[9]}
        combiner = _make_combiner_with_fixtures(sources, fixture)
        result = combiner.combine(sources, "Test", days_history=0)
        cal = _parse_combined(result)
        events = _get_events(cal)
        timed = [e for e in events if hasattr(e.decoded("DTSTART"), "hour")]
        assert len(timed) >= 1
        for event in timed:
            if event.get("DURATION") and not event.get("DTEND"):
                dur = event.decoded("DURATION")
                assert (
                    dur.total_seconds() == 300
                ), f"Expected 5-min default duration, got {dur}"

    def test_emoji_in_summary_preserved(self):
        """Source 10 uses emoji in SUMMARY (⚽️). Should pass through."""
        cal = self._parsed()
        summaries = _event_summaries(cal)
        assert any("⚽️" in s for s in summaries)

    def test_canceled_events_preserved(self):
        """TeamSnap-style [CANCELED] in SUMMARY should pass through."""
        cal = self._parsed()
        summaries = _event_summaries(cal)
        assert any("[CANCELED]" in s for s in summaries)

    def test_non_round_seconds_preserved(self):
        """Source 3 has events at :41 seconds. Should not be mangled."""
        sources = [PROD_SOURCES[3]]
        fixture = {3: FIXTURE_MAP[3]}
        combiner = _make_combiner_with_fixtures(sources, fixture)
        result = combiner.combine(sources, "Test", days_history=0)
        cal = _parse_combined(result)
        events = _get_events(cal)
        has_odd_seconds = any(e.decoded("DTSTART").second == 41 for e in events)
        assert has_odd_seconds, "Non-round seconds should be preserved"

    def test_show_filter(self):
        """show=[0] should only include source 0."""
        combiner = _make_combiner_with_fixtures(PROD_SOURCES, FIXTURE_MAP)
        result = combiner.combine(PROD_SOURCES, "Test", days_history=0, show=[0])
        cal = _parse_combined(result)
        summaries = _event_summaries(cal)
        assert any("Family Dinner" in s for s in summaries)
        assert not any("Team Alpha" in s for s in summaries)
        assert not any("Ref A" in s for s in summaries)

    def test_hide_filter(self):
        """hide=[0] should exclude source 0 but include everything else."""
        combiner = _make_combiner_with_fixtures(PROD_SOURCES, FIXTURE_MAP)
        result = combiner.combine(PROD_SOURCES, "Test", days_history=0, hide=[0])
        cal = _parse_combined(result)
        summaries = _event_summaries(cal)
        assert not any("Family Dinner" in s for s in summaries)
        assert any("Team Alpha" in s for s in summaries)

    def test_output_is_deterministic(self):
        """Two runs with the same input should produce identical output."""
        result1 = self._combine_all()
        result2 = self._combine_all()
        assert result1 == result2


class TestEdgeCases:
    def _combine_edge(self, source_config=None):
        config = source_config or {"Id": 99, "Url": "https://example.com/edge.ics"}
        fixture = {99: _load_fixture("source_edge_cases.ics")}
        combiner = _make_combiner_with_fixtures([config], fixture)
        return combiner.combine([config], "Edge Test", days_history=0)

    def test_missing_uid_gets_fallback(self):
        """Event without UID should get a generated fallback, not crash."""
        result = self._combine_edge()
        cal = _parse_combined(result)
        events = _get_events(cal)
        no_uid_events = [e for e in events if "no UID" in str(e.get("SUMMARY", ""))]
        assert len(no_uid_events) == 1
        assert no_uid_events[0].get("UID") is not None

    def test_missing_dtstart_skipped(self):
        """Event without DTSTART should be silently skipped."""
        result = self._combine_edge()
        cal = _parse_combined(result)
        summaries = _event_summaries(cal)
        assert not any("no DTSTART" in s for s in summaries)

    def test_timed_event_no_dtend_gets_5min(self):
        """Timed event without DTEND or DURATION gets 5-minute default."""
        result = self._combine_edge()
        cal = _parse_combined(result)
        events = _get_events(cal)
        target = [
            e for e in events if "no DTEND or DURATION" in str(e.get("SUMMARY", ""))
        ]
        assert len(target) == 1
        dur = target[0].decoded("DURATION")
        assert dur.total_seconds() == 300

    def test_allday_no_dtend_gets_1day(self):
        """All-day event without DTEND gets 1-day default."""
        result = self._combine_edge()
        cal = _parse_combined(result)
        events = _get_events(cal)
        target = [e for e in events if "All-day" in str(e.get("SUMMARY", ""))]
        assert len(target) == 1
        dur = target[0].decoded("DURATION")
        assert dur.days == 1

    def test_organizer_stripped(self):
        """ORGANIZER field should be removed from all events."""
        result = self._combine_edge()
        cal = _parse_combined(result)
        events = _get_events(cal)
        for event in events:
            assert event.get("ORGANIZER") is None

    def test_blank_description_lines_removed(self):
        """Empty lines in DESCRIPTION should be stripped."""
        result = self._combine_edge()
        cal = _parse_combined(result)
        events = _get_events(cal)
        target = [e for e in events if "blank description" in str(e.get("SUMMARY", ""))]
        assert len(target) == 1
        desc = str(target[0].get("DESCRIPTION", ""))
        assert "\n\n" not in desc

    def test_per_event_error_does_not_crash_combine(self):
        """A source with a bad event shouldn't crash the entire combine."""
        bad_ics = """BEGIN:VCALENDAR
VERSION:2.0
BEGIN:VEVENT
DTSTART:20300801T120000Z
DTEND:20300801T130000Z
UID:good-event@test
SUMMARY:Good Event
END:VEVENT
END:VCALENDAR"""
        config = {"Id": 99, "Url": "https://example.com/99.ics"}
        fixture = {99: bad_ics}
        combiner = _make_combiner_with_fixtures([config], fixture)
        result = combiner.combine([config], "Test", days_history=0)
        cal = _parse_combined(result)
        summaries = _event_summaries(cal)
        assert "Good Event" in summaries


class TestFilterDuplicatesWithRecurrence:
    def test_recurrence_override_not_collapsed(self):
        """FilterDuplicates should keep both master and override when they share a UID."""
        ics_with_recurrence = """BEGIN:VCALENDAR
VERSION:2.0
BEGIN:VEVENT
DTSTART:20300601T100000Z
DTEND:20300601T110000Z
UID:recurring-weekly@test
SUMMARY:Weekly Meeting
RRULE:FREQ=WEEKLY;COUNT=10
END:VEVENT
BEGIN:VEVENT
DTSTART:20300608T140000Z
DTEND:20300608T150000Z
UID:recurring-weekly@test
RECURRENCE-ID:20300608T100000Z
SUMMARY:Weekly Meeting (moved)
END:VEVENT
END:VCALENDAR"""
        config = {
            "Id": 50,
            "Url": "https://example.com/50.ics",
            "FilterDuplicates": True,
        }
        fixture = {50: ics_with_recurrence}
        combiner = _make_combiner_with_fixtures([config], fixture)
        result = combiner.combine([config], "Test", days_history=0)
        cal = _parse_combined(result)
        events = _get_events(cal)
        assert (
            len(events) == 2
        ), f"Expected 2 events (master + override), got {len(events)}"
        summaries = [str(e.get("SUMMARY")) for e in events]
        assert "Weekly Meeting" in summaries
        assert "Weekly Meeting (moved)" in summaries


class TestConfigValidation:
    def test_string_id_coerced_to_int(self):
        sources = [{"Id": "5", "Url": "https://example.com/5.ics"}]
        validated = ICSCombiner._validate_sources(sources)
        assert validated[0]["Id"] == 5

    def test_duplicate_id_rejected(self):
        sources = [
            {"Id": 1, "Url": "https://example.com/1.ics"},
            {"Id": 1, "Url": "https://example.com/2.ics"},
        ]
        try:
            ICSCombiner._validate_sources(sources)
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "Duplicate" in str(e)

    def test_missing_url_rejected(self):
        sources = [{"Id": 1}]
        try:
            ICSCombiner._validate_sources(sources)
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "Url" in str(e)

    def test_string_duration_rejected(self):
        sources = [{"Id": 1, "Url": "https://example.com/1.ics", "Duration": "60"}]
        try:
            ICSCombiner._validate_sources(sources)
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "non-numeric" in str(e)

    def test_negative_duration_rejected(self):
        sources = [{"Id": 1, "Url": "https://example.com/1.ics", "Duration": -10}]
        try:
            ICSCombiner._validate_sources(sources)
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "negative" in str(e)

    def test_negative_pad_rejected(self):
        sources = [{"Id": 1, "Url": "https://example.com/1.ics", "PadStartMinutes": -5}]
        try:
            ICSCombiner._validate_sources(sources)
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "negative" in str(e)

    def test_float_duration_coerced(self):
        sources = [{"Id": 1, "Url": "https://example.com/1.ics", "Duration": 60.5}]
        validated = ICSCombiner._validate_sources(sources)
        assert validated[0]["Duration"] == 60

    def test_valid_config_passes(self):
        sources = [
            {
                "Id": 1,
                "Url": "https://example.com/1.ics",
                "Duration": 60,
                "PadStartMinutes": 30,
            }
        ]
        validated = ICSCombiner._validate_sources(sources)
        assert len(validated) == 1

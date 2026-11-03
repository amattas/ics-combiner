"""Property and corpus-replay tests for the untrusted-feed parsing path.

Remote feed bytes go through ``decode -> _normalize_ics_text -> _parse_ics_text``
(see ``ICSCombiner._fetch_source_ics``); string DTSTART values left by icalendar
go through ``_parse_datetime_or_date``. Exception contract for all three: they
never raise on any input. ``_normalize_ics_text`` always returns a ``str``,
``_parse_datetime_or_date`` returns a ``datetime``, ``date`` or ``None``, and
``_parse_ics_text`` returns a ``Calendar`` or ``None``.

The corpus under ``fuzz/corpus/`` seeds the atheris target ``fuzz/fuzz_parse_ics.py``;
replaying it here keeps every past crash input a regression test on every PR.
"""

import importlib.util
from datetime import UTC, date, datetime, timedelta, timezone
from functools import cache
from pathlib import Path

import pytest
from hypothesis import example, given
from hypothesis import strategies as st

from src.services.ics_combiner import ICSCombiner

FUZZ_DIR = Path(__file__).resolve().parent.parent / "fuzz"
CORPUS = FUZZ_DIR / "corpus"
CORPUS_FILES = sorted(p for p in CORPUS.glob("*/*") if p.is_file())


@cache
def _target(name):
    spec = importlib.util.spec_from_file_location(name, FUZZ_DIR / f"{name}.py")
    assert spec is not None and spec.loader is not None, (
        f"no fuzz target for corpus directory {name}"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.test_one_input


# Offsets fromisoformat accepts: strictly inside +/-24h, minute resolution.
_offsets = st.integers(min_value=-(24 * 60 - 1), max_value=24 * 60 - 1).map(
    lambda minutes: timezone(timedelta(minutes=minutes))
)
_naive_datetimes = st.datetimes().map(lambda dt: dt.replace(microsecond=0))
_aware_datetimes = st.builds(
    lambda dt, tz: dt.replace(tzinfo=tz), _naive_datetimes, _offsets
)

# Lines shaped like the non-RFC5545 forms the normalizer rewrites, plus noise.
_feed_lines = st.one_of(
    st.builds(
        lambda prop, dt, sep: f"{prop}:{dt.isoformat(sep=sep)}",
        st.sampled_from(["DTSTART", "DTEND"]),
        st.one_of(_naive_datetimes, _aware_datetimes),
        st.sampled_from([" ", "T"]),
    ),
    st.from_regex(
        r"\A(DTSTART|DTEND):\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}([+-]\d{2}:\d{2})?\Z"
    ),
    st.text(),
)
_feeds = st.lists(_feed_lines, max_size=8).map("\n".join)


@given(_feeds)
@example("DTSTART:9999-12-31 23:59:59-23:59")
@example("DTEND:0001-01-01T00:00:00+23:59")
def test_normalize_ics_text_never_raises_and_is_idempotent(text):
    normalized = ICSCombiner._normalize_ics_text(text)

    assert isinstance(normalized, str)
    assert ICSCombiner._normalize_ics_text(normalized) == normalized


@given(
    st.sampled_from(["DTSTART", "DTEND"]), _aware_datetimes, st.sampled_from([" ", "T"])
)
def test_normalize_ics_text_rewrites_offset_times_to_the_same_utc_instant(
    prop, dt, sep
):
    normalized = ICSCombiner._normalize_ics_text(f"{prop}:{dt.isoformat(sep=sep)}")

    try:
        utc = dt.astimezone(UTC)
    except OverflowError:
        # The UTC instant is outside years 1-9999: the line is left as-is.
        assert normalized == f"{prop}:{dt.isoformat(sep=sep)}"
    else:
        assert (
            normalized
            == f"{prop}:{utc.isoformat().replace('-', '').replace(':', '')[:15]}Z"
        )


@given(st.text())
@example("")
@example("2025-11-01 13:30:00+00:00")
def test_parse_datetime_or_date_never_raises(text):
    parsed = ICSCombiner._parse_datetime_or_date(text)

    assert parsed is None or isinstance(parsed, (datetime, date))


@given(
    st.one_of(_naive_datetimes, _aware_datetimes, st.dates()),
    st.sampled_from([" ", "T"]),
)
def test_parse_datetime_or_date_round_trips_iso_values(value, sep):
    text = (
        value.isoformat(sep=sep) if isinstance(value, datetime) else value.isoformat()
    )

    assert ICSCombiner._parse_datetime_or_date(f"  {text}\n") == value


def test_corpus_is_present():
    assert CORPUS_FILES, f"no seed corpus under {CORPUS}"


@pytest.mark.parametrize(
    "path", CORPUS_FILES, ids=lambda p: f"{p.parent.name}/{p.name}"
)
def test_fuzz_corpus_replays_within_the_exception_contract(path):
    _target(path.parent.name)(path.read_bytes())

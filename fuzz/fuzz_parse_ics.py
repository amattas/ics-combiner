"""Atheris target: untrusted remote feed bytes through normalize + parse.

Mirrors ``ICSCombiner._fetch_source_ics``: decode the response body as UTF-8
with replacement, rewrite non-RFC5545 datetimes, then parse with icalendar.
Contract (see tests/test_feed_parsing_properties.py): nothing raises, and the
result is a ``Calendar`` or ``None``. Any exception is a crash.
"""

import sys

from icalendar import Calendar

from src.services.ics_combiner import ICSCombiner


def test_one_input(data: bytes) -> None:
    text = data.decode("utf-8", errors="replace")

    parsed = ICSCombiner._parse_ics_text(ICSCombiner._normalize_ics_text(text))

    if parsed is not None and not isinstance(parsed, Calendar):
        raise AssertionError(f"unexpected parse result {type(parsed)!r}")


def main() -> None:
    import atheris

    atheris.instrument_all()
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()

"""The one shared sanitiser used by core (titles, headers, banners) and output."""

import pytest

from homenet.core._text import clean_text
from homenet.output import _clean


@pytest.mark.parametrize(
    ("raw", "max_len", "clean"),
    [
        ("\x1b[31mRed\x1b[0m", None, "?[31mRed?[0m"),  # ESC / CSI
        ("Evil\x1b]0;pwn\x07", None, "Evil?]0;pwn?"),  # OSC + BEL
        ("a\x00b\x7fc", None, "a?b?c"),  # C0 + DEL
        ("x\u009bterm\u0085", None, "x?term?"),  # C1
        ("evil\u202egnp.exe\u200b", None, "evil?gnp.exe?"),  # bidi override, zero-width
        ("  a\n\tb  ", None, "a??b"),  # newline/tab replaced, outer space trimmed
        ("é ok 日本", None, "é ok 日本"),
        ("", None, None),
        (None, None, None),
        ("a" * 500, 200, "a" * 200),  # length cap
    ],
)
def test_clean(raw, max_len, clean):
    assert clean_text(raw, max_len) == clean


def test_output_uses_the_shared_sanitiser():
    assert _clean is clean_text

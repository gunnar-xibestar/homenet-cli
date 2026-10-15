"""Text sanitising for untrusted network strings (titles, headers, banners)."""

from __future__ import annotations

import unicodedata

DEFAULT_MAX_LEN = 200


def _clean(text: object, max_len: int = DEFAULT_MAX_LEN) -> str | None:
    """Drop control/format chars (incl. ESC, C1, bidi overrides), collapse whitespace.

    Returns None for empty results. Output is capped at ``max_len`` characters.
    """
    if text is None:
        return None
    out = []
    for ch in str(text):
        if ch in "\t\n\r\f\v":
            out.append(" ")
        elif unicodedata.category(ch) in ("Cc", "Cf", "Cs", "Co", "Cn"):
            continue
        else:
            out.append(ch)
    cleaned = " ".join("".join(out).split())[:max_len]
    return cleaned or None

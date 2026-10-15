"""Shared sanitiser for untrusted network strings (hostnames, vendors, titles, banners)."""

from __future__ import annotations

DEFAULT_MAX_LEN = 200


def clean_text(value: object, max_len: int | None = None) -> str | None:
    """Replace every non-printable character with ``?`` and trim surrounding space.

    Covers ESC/CSI/OSC sequences, C0/C1 controls, newlines and tabs, bidi
    overrides and other format characters, so untrusted text cannot change the
    terminal. Returns None for empty results; ``max_len`` optionally caps the length.
    """
    if value is None:
        return None
    visible = "".join(ch if ch.isprintable() else "?" for ch in str(value)).strip()
    if max_len is not None:
        visible = visible[:max_len].rstrip()
    return visible or None

#!/usr/bin/env python3
"""Check validate_target against the scan-guard property.

The bound is every IPv4 /16 (65,536 of them) and, for each, every prefix
from 16 through 32 on that block's base address. Prefixes 0 through 15 are
checked on every aligned subnet of the five allowed ranges that is shorter
than /16, plus every prefix 0 through 15 on eight fixed public bases.
force=False is checked for the same /16-and-longer set against local network
192.168.1.0/24. Malformed strings are a fixed list, not every possible string.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "src"))

from homenet.core.runner import (  # noqa: E402
    InvalidTargetError,
    TargetNotAllowedError,
    validate_target,
)

# Promise, written here so a change to runner.py constants cannot silently
# move the goalposts. These are the ranges and the /16 floor in
# src/homenet/core/runner.py (_ALLOWED_RANGES, MAX_PREFIX_LEN).
SPEC_RANGES = (
    (0x0A000000, 8),  # 10.0.0.0/8
    (0xAC100000, 12),  # 172.16.0.0/12
    (0xC0A80000, 16),  # 192.168.0.0/16
    (0xA9FE0000, 16),  # 169.254.0.0/16
    (0x7F000000, 8),  # 127.0.0.0/8
)
MIN_PREFIX = 16
LOCAL = "192.168.1.0/24"
LOCAL_BASE = 0xC0A80100
LOCAL_PREFIX = 24
PUBLIC_BASES = (
    0x00000000,  # 0.0.0.0
    0x01020304,  # 1.2.3.4
    0x08080808,  # 8.8.8.8
    0x0B000000,  # 11.0.0.0
    0xAC200000,  # 172.32.0.0
    0xC0A70000,  # 192.167.0.0
    0xCB007100,  # 203.0.113.0
    0xFFFFFFFF,  # 255.255.255.255
)
MALFORMED = (
    "",
    "   ",
    "-10.0.0.0",
    "10.0.0.0 24",
    "::1",
    "2001:db8::/32",
    "10.0.0.0/33",
    "not-an-ip",
    "10.0.0.0/16 extra",
)


def ipv4(value: int) -> str:
    return f"{(value >> 24) & 255}.{(value >> 16) & 255}.{(value >> 8) & 255}.{value & 255}"


def aligned(addr: int, prefix: int) -> int:
    if prefix <= 0:
        return 0
    shift = 32 - prefix
    return (addr & ((0xFFFFFFFF << shift) & 0xFFFFFFFF)) & 0xFFFFFFFF


def in_spec(addr: int, prefix: int) -> bool:
    """True when a force=True scan of this network is allowed by the promise."""
    if prefix < MIN_PREFIX or prefix > 32:
        return False
    base = aligned(addr, prefix)
    for range_addr, range_prefix in SPEC_RANGES:
        if prefix < range_prefix:
            continue
        if aligned(base, range_prefix) == range_addr:
            return True
    return False


def in_local(addr: int, prefix: int) -> bool:
    if prefix < LOCAL_PREFIX:
        return False
    return aligned(addr, LOCAL_PREFIX) == LOCAL_BASE


def classify(text: str, *, force: bool, local: str | None) -> str:
    try:
        net = validate_target(text, local, force)
    except TargetNotAllowedError:
        return "refused"
    except InvalidTargetError:
        return "invalid"
    return f"accepted {net}"


def expect(text: str, want: str, *, force: bool, local: str | None, failures: list[str]) -> None:
    got = classify(text, force=force, local=local)
    if got != want:
        failures.append(
            f"validate_target({text!r}, local={local!r}, force={force}) "
            f"-> {got}; property says {want}"
        )


def check_block(base: int, prefixes: range, failures: list[str], limit: int) -> int:
    checked = 0
    for prefix in prefixes:
        network = aligned(base, prefix)
        text = f"{ipv4(network)}/{prefix}"
        allowed = in_spec(network, prefix)
        expect(
            text,
            "accepted " + text if allowed else "refused",
            force=True,
            local=None,
            failures=failures,
        )
        local_ok = allowed and in_local(network, prefix)
        expect(
            text,
            "accepted " + text if local_ok else "refused",
            force=False,
            local=LOCAL,
            failures=failures,
        )
        checked += 2
        if len(failures) >= limit:
            return checked
    return checked


def main() -> int:
    failures: list[str] = []
    limit = 8
    checked = 0
    for index in range(65536):
        checked += check_block(index << 16, range(16, 33), failures, limit)
        if len(failures) >= limit:
            break
    if len(failures) < limit:
        for range_addr, range_prefix in SPEC_RANGES:
            start = max(range_prefix, 0)
            for prefix in range(start, MIN_PREFIX):
                count = 1 << (prefix - range_prefix)
                span = 1 << (32 - prefix)
                for step in range(count):
                    checked += check_block(
                        range_addr + step * span,
                        range(prefix, prefix + 1),
                        failures,
                        limit,
                    )
                    if len(failures) >= limit:
                        break
                if len(failures) >= limit:
                    break
    if len(failures) < limit:
        for base in PUBLIC_BASES:
            checked += check_block(base, range(0, MIN_PREFIX), failures, limit)
            if len(failures) >= limit:
                break
    if len(failures) < limit:
        for text in MALFORMED:
            expect(text, "invalid", force=True, local=None, failures=failures)
            checked += 1
    if failures:
        print(f"scan guard failed ({checked} cases before stop)")
        for item in failures:
            print(item)
        return 1
    print(f"scan guard passed ({checked} cases)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Environment checks for ``homenet doctor``.

These functions never print and never call ``sys.exit``. The CLI owns
all user-facing output.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess  # noqa: S404 - argument lists only, never shell=True
from dataclasses import dataclass
from pathlib import Path

CAP_NET_RAW = 13

_PACKAGES = {
    "nmap": "nmap",
    "ip": "iproute2",
    "ping": "iputils-ping",
}
_VERSION_FLAGS = {
    "nmap": "--version",
    "ip": "-V",
    "ping": "-V",
}
_VERSION_RE = re.compile(r"\d+(?:\.\d+)+\w*")
_PRIVILEGE_HINT = (
    "Re-run with sudo, or grant nmap raw sockets: sudo setcap cap_net_raw+ep $(which nmap)"
)


@dataclass
class CheckResult:
    """One doctor check.

    ``detail`` is the tool version when the tool is installed.
    ``fix_hint`` is set when ``ok`` is false.
    ``severity`` is ``ok``, ``warning``, or ``error``. It defaults to ``error``
    so a failed check stays fatal unless the caller marks it a warning.
    """

    name: str
    ok: bool
    detail: str
    fix_hint: str | None = None
    severity: str = "error"


def check_tool(name: str) -> CheckResult:
    """Return ok=false and a fix hint when ``name`` is not on PATH."""
    path = shutil.which(name)
    if path is None:
        package = _PACKAGES.get(name, name)
        return CheckResult(
            name,
            False,
            f"{name} is not installed (not found on PATH).",
            f"sudo apt install {package}",
        )
    flag = _VERSION_FLAGS.get(name, "--version")
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argument list from shutil.which
            [path, flag],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return CheckResult(
            name, True, f"{name} found at {path} (version unknown: {exc})", severity="ok"
        )
    text = (proc.stdout or "") + (proc.stderr or "")
    match = _VERSION_RE.search(text)
    version = match.group(0) if match else "unknown"
    return CheckResult(name, True, f"{name} {version}", severity="ok")


def _has_cap_net_raw(status_text: str) -> bool:
    match = re.search(r"^CapEff:\s*([0-9a-fA-F]+)", status_text, re.MULTILINE)
    if match is None:
        return False
    try:
        effective = int(match.group(1), 16)
    except ValueError:
        return False
    return bool(effective & (1 << CAP_NET_RAW))


def check_privileges() -> CheckResult:
    """Return ok=false (and never raise) when this process cannot scan raw sockets."""
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None:
        return CheckResult(
            "privileges",
            False,
            "privilege check is only available on Linux",
            _PRIVILEGE_HINT,
        )
    if geteuid() == 0:
        return CheckResult(
            "privileges", True, "running as root; full scan detail available", severity="ok"
        )
    try:
        status = Path("/proc/self/status").read_text(encoding="utf-8")
    except OSError:
        status = ""
    if _has_cap_net_raw(status):
        return CheckResult("privileges", True, "CAP_NET_RAW is available", severity="ok")
    return CheckResult(
        "privileges",
        False,
        "running as a normal user: scans work, but MAC addresses and SYN scans "
        "need extra privileges",
        _PRIVILEGE_HINT,
        severity="warning",
    )


def _default_route(text: str) -> tuple[str, str] | None:
    """Return ``(interface, gateway_hex)`` for the first default route."""
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 3 and fields[1] == "00000000":
            return fields[0], fields[2]
    return None


def _decode_le_ipv4(hex_word: str) -> str | None:
    try:
        word = int(hex_word, 16)
    except ValueError:
        return None
    octets = [(word >> (8 * shift)) & 0xFF for shift in range(4)]
    return ".".join(str(octet) for octet in octets)


def _operstate(iface: str) -> str:
    try:
        state = Path(f"/sys/class/net/{iface}/operstate").read_text(encoding="utf-8").strip()
    except OSError:
        return "unknown"
    return state or "unknown"


def check_network() -> CheckResult:
    """Check that a default route exists and report its interface."""
    try:
        text = Path("/proc/net/route").read_text(encoding="utf-8")
    except OSError:
        text = ""
    route = _default_route(text)
    if route is None:
        return CheckResult(
            "network",
            False,
            "no default route: you don't seem to be connected to a network",
            "Connect to Wi-Fi or Ethernet, then run this again.",
        )
    iface, gateway_hex = route
    state = _operstate(iface)
    if state not in ("up", "unknown"):
        return CheckResult(
            "network",
            False,
            f"default interface {iface} is {state}",
            f"Bring the interface up or reconnect: nmcli device connect {iface}",
        )
    gateway = None if gateway_hex == "00000000" else _decode_le_ipv4(gateway_hex)
    if gateway:
        detail = f"default route via {gateway}, interface {iface} ({state})"
    else:
        detail = f"default route on interface {iface} ({state})"
    return CheckResult("network", True, detail, severity="ok")


def check_ping() -> CheckResult:
    """Stub: report whether ``ping`` is installed.

    Packet-loss against the gateway is filled in by Net Core. A missing
    ``ping`` is an error; finding it is severity ``ok``.
    """
    return check_tool("ping")


def run_all_checks() -> list[CheckResult]:
    """Run the nmap, ip, privileges, network, and ping checks, in that order."""
    return [
        check_tool("nmap"),
        check_tool("ip"),
        check_privileges(),
        check_network(),
        check_ping(),
    ]

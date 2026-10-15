"""Environment checks for ``homenet doctor``. Never prints or calls ``sys.exit``."""

from __future__ import annotations

import os
import re
import shutil
import subprocess  # noqa: S404 - argument lists only
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

CAP_NET_RAW = 13

# binary -> (version args, apt package)
_TOOLS: dict[str, tuple[tuple[str, ...], str]] = {
    "nmap": (("--version",), "nmap"),
    "ip": (("-V",), "iproute2"),
    "ping": (("-V",), "iputils-ping"),
}


@dataclass
class CheckResult:
    name: str
    ok: bool
    detail: str
    fix_hint: str | None = None


def _run_version(args: Sequence[str]) -> str:
    proc = subprocess.run(  # noqa: S603 - fixed argument list
        list(args), capture_output=True, text=True, timeout=5, check=False
    )
    return (proc.stdout or "") + (proc.stderr or "")


def _read_text(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def check_tool(
    name: str,
    which: Callable[[str], str | None] | None = None,
    run: Callable[[Sequence[str]], str] | None = None,
) -> CheckResult:
    """Check ``name`` is on PATH and read its version."""
    which = which or shutil.which
    run = run or _run_version
    version_args, package = _TOOLS.get(name, (("--version",), name))
    path = which(name)
    if path is None:
        return CheckResult(
            name,
            False,
            f"{name} is not installed (not found on PATH).",
            f"sudo apt install {package}",
        )
    try:
        out = run([path, *version_args])
    except (OSError, subprocess.SubprocessError) as exc:
        return CheckResult(name, True, f"found at {path} (version unknown: {exc})")
    m = re.search(r"\d+(?:\.\d+)+\w*", out)
    version = m.group(0) if m else "unknown"
    return CheckResult(name, True, f"{name} {version} at {path}")


def _has_cap_net_raw(status_text: str) -> bool:
    m = re.search(r"^CapEff:\s*([0-9a-fA-F]+)", status_text, re.MULTILINE)
    return bool(m and int(m.group(1), 16) & (1 << CAP_NET_RAW))


def check_privileges(
    geteuid: Callable[[], int] | None = None,
    read_text: Callable[[str], str] | None = None,
    environ: dict[str, str] | None = None,
) -> CheckResult:
    """Check for root, sudo or CAP_NET_RAW (needed for ARP/SYN scans and MACs)."""
    env = os.environ if environ is None else environ
    geteuid = geteuid or os.geteuid
    read_text = read_text or _read_text
    if geteuid() == 0:
        how = "via sudo" if env.get("SUDO_USER") else "as root"
        return CheckResult("privileges", True, f"running {how}; full scan detail available")
    try:
        caps = _has_cap_net_raw(read_text("/proc/self/status"))
    except OSError:
        caps = False
    if caps:
        return CheckResult("privileges", True, "CAP_NET_RAW is available")
    return CheckResult(
        "privileges",
        False,
        "running as a normal user: scans work, but MAC addresses/vendors and SYN scans "
        "need extra privileges",
        "Re-run with sudo, or grant nmap raw-socket access once: "
        "sudo setcap cap_net_raw,cap_net_admin+eip $(which nmap)",
    )


def _default_route(text: str) -> tuple[str, str] | None:
    for line in text.splitlines()[1:]:
        f = line.split()
        if len(f) >= 3 and f[1] == "00000000":
            return f[0], f[2]
    return None


def check_network(read_text: Callable[[str], str] | None = None) -> CheckResult:
    """Check there is a default route and that its interface is up."""
    read_text = read_text or _read_text
    try:
        route = _default_route(read_text("/proc/net/route"))
    except OSError:
        route = None
    if route is None:
        return CheckResult(
            "network",
            False,
            "no default route: you don't seem to be connected to a network",
            "Connect to Wi-Fi or Ethernet, then run this again.",
        )
    iface = route[0]
    try:
        state = read_text(f"/sys/class/net/{iface}/operstate").strip()
    except OSError:
        state = "unknown"
    if state not in ("up", "unknown"):
        return CheckResult(
            "network",
            False,
            f"default interface {iface} is {state}",
            f"Bring the interface up or reconnect: nmcli device connect {iface}",
        )
    return CheckResult("network", True, f"default route via interface {iface} ({state})")


def run_all_checks() -> list[CheckResult]:
    """Run nmap, ip, privileges and network checks, in that order."""
    return [check_tool("nmap"), check_tool("ip"), check_privileges(), check_network()]

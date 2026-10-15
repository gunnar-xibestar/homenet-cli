"""Environment checks for ``homenet doctor``. Never prints or calls ``sys.exit``."""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import socket
import struct
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
    # "ok" | "warning" | "error". Optional and additive: lets the CLI show
    # non-fatal problems (e.g. no root) as warnings. ok/name/detail/fix_hint are unchanged.
    severity: str = "error"


def _run_version(args: Sequence[str], timeout: float = 5) -> str:
    proc = subprocess.run(  # noqa: S603 - fixed argument list
        list(args), capture_output=True, text=True, timeout=timeout, check=False
    )
    return (proc.stdout or "") + (proc.stderr or "")


def _ok(name: str, detail: str) -> CheckResult:
    return CheckResult(name, True, detail, None, "ok")


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
            "error",
        )
    try:
        out = run([path, *version_args])
    except (OSError, subprocess.SubprocessError) as exc:
        return _ok(name, f"found at {path} (version unknown: {exc})")
    m = re.search(r"\d+(?:\.\d+)+\w*", out)
    version = m.group(0) if m else "unknown"
    return _ok(name, f"{name} {version} at {path}")


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
        return _ok("privileges", f"running {how}; full scan detail available")
    try:
        caps = _has_cap_net_raw(read_text("/proc/self/status"))
    except OSError:
        caps = False
    if caps:
        return _ok("privileges", "CAP_NET_RAW is available")
    return CheckResult(
        "privileges",
        False,
        "running as a normal user: scans work, but MAC addresses/vendors and SYN scans "
        "need extra privileges",
        "Easiest: re-run with sudo, e.g. `sudo homenet scan`. "
        "Advanced alternative: `sudo setcap cap_net_raw+eip /usr/bin/nmap` (use the path "
        "from `command -v nmap`) and run nmap with --privileged. Be careful: this lets "
        "every user on this computer send raw network packets through nmap, not just you.",
        "warning",
    )


def _default_route(text: str) -> tuple[str, str | None] | None:
    """Return (interface, gateway) of the default route in /proc/net/route."""
    for line in text.splitlines()[1:]:
        f = line.split()
        if len(f) >= 3 and f[1] == "00000000":
            try:
                gw = socket.inet_ntoa(struct.pack("<L", int(f[2], 16)))
            except (ValueError, struct.error):
                gw = None
            return f[0], None if gw in (None, "0.0.0.0") else gw  # noqa: S104
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
            "error",
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
            "error",
        )
    return _ok("network", f"default route via interface {iface} ({state})")


def check_ping(
    target: str | None = None,
    which: Callable[[str], str | None] | None = None,
    run: Callable[[Sequence[str]], str] | None = None,
    read_text: Callable[[str], str] | None = None,
) -> CheckResult:
    """Ping the default gateway (or ``target``) once and report packet loss."""
    which = which or shutil.which
    run = run or (lambda args: _run_version(args, timeout=5))
    read_text = read_text or _read_text
    if target is None:
        try:
            route = _default_route(read_text("/proc/net/route"))
        except OSError:
            route = None
        target = route[1] if route else None
    if target is None:
        return CheckResult(
            "ping",
            False,
            "no default gateway to ping",
            "Connect to Wi-Fi or Ethernet, then run this again.",
            "error",
        )
    try:
        target = str(ipaddress.ip_address(target))
    except ValueError:
        return CheckResult("ping", False, f"{target!r} is not a valid IP address", None, "error")
    path = which("ping")
    if path is None:
        return CheckResult(
            "ping", False, "ping is not installed", "sudo apt install iputils-ping", "error"
        )
    try:
        out = run([path, "-c", "3", "-W", "1", "-q", target])
    except (OSError, subprocess.SubprocessError) as exc:
        return CheckResult("ping", False, f"could not run ping: {exc}", None, "error")
    m = re.search(r"(\d+(?:\.\d+)?)% packet loss", out)
    if m is None:
        return CheckResult("ping", False, f"could not read ping output for {target}", None, "error")
    loss = float(m.group(1))
    if loss >= 100:
        return CheckResult(
            "ping",
            False,
            f"gateway {target} did not answer (100% packet loss)",
            "Check your Wi-Fi/cable; some routers ignore ping, so this may be harmless.",
            "warning",
        )
    if loss > 0:
        return CheckResult(
            "ping",
            True,
            f"gateway {target} reachable with {loss:g}% packet loss",
            "Some packets were lost; a weak Wi-Fi signal is a common cause.",
            "warning",
        )
    return _ok("ping", f"gateway {target} reachable (0% packet loss)")


def run_all_checks(
    which: Callable[[str], str | None] | None = None,
    run: Callable[[Sequence[str]], str] | None = None,
    geteuid: Callable[[], int] | None = None,
    read_text: Callable[[str], str] | None = None,
    environ: dict[str, str] | None = None,
) -> list[CheckResult]:
    """Run nmap, ip, privileges, network and ping checks, in that order.

    All I/O hooks are optional so tests can pass fakes.
    """
    return [
        check_tool("nmap", which=which, run=run),
        check_tool("ip", which=which, run=run),
        check_privileges(geteuid=geteuid, read_text=read_text, environ=environ),
        check_network(read_text=read_text),
        check_ping(which=which, run=run, read_text=read_text),
    ]

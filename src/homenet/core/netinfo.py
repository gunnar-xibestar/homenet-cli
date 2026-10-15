"""Detect the active interface, gateway and subnet (for ``whoami-net``).

Uses ``ip -j route`` / ``ip -j addr``; falls back to ``/proc/net/route`` when
``ip`` is unavailable. All I/O goes through injectable callables so tests can
mock it. Never prints.
"""

from __future__ import annotations

import ipaddress
import json
import shutil
import socket
import struct
import subprocess  # noqa: S404 - argument lists only
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

CommandRunner = Callable[[Sequence[str]], str]
FileReader = Callable[[str], str]


class NetInfoError(Exception):
    def __init__(self, message: str, hint: str | None = None) -> None:
        super().__init__(message)
        self.hint = hint


@dataclass(frozen=True)
class NetInfo:
    interface: str
    ip: str | None
    gateway: str | None
    subnet: str | None


def _run_ip(args: Sequence[str], timeout: float = 5.0) -> str:
    ip = shutil.which("ip")
    if ip is None:
        raise FileNotFoundError("ip")
    proc = subprocess.run(  # noqa: S603 - fixed argument list
        [ip, *args], capture_output=True, text=True, timeout=timeout, check=True
    )
    return proc.stdout


def _read_file(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def parse_default_route(routes: list[dict]) -> tuple[str, str | None]:
    """Return (interface, gateway) of the lowest-metric default route."""
    defaults = [r for r in routes if r.get("dst") == "default" and r.get("dev")]
    if not defaults:
        raise NetInfoError(
            "No default route found; you may not be connected to a network.",
            "Connect to Wi-Fi or Ethernet and try again.",
        )
    best = min(defaults, key=lambda r: r.get("metric", 0))
    return best["dev"], best.get("gateway")


def parse_interface_addr(addrs: list[dict], ifname: str) -> tuple[str | None, str | None]:
    """Return (ip, subnet) for the interface's first IPv4 address."""
    for iface in addrs:
        if iface.get("ifname") != ifname:
            continue
        for a in iface.get("addr_info", []):
            if a.get("family") == "inet" and "local" in a:
                net = ipaddress.ip_interface(f"{a['local']}/{a.get('prefixlen', 32)}").network
                return a["local"], str(net)
    return None, None


def parse_proc_route(text: str) -> tuple[str, str | None]:
    """Parse /proc/net/route (hex little-endian) for the default route."""
    best = None
    for line in text.splitlines()[1:]:
        f = line.split()
        if len(f) < 8 or f[1] != "00000000":
            continue
        metric = int(f[6])
        if best is None or metric < best[0]:
            gw = socket.inet_ntoa(struct.pack("<L", int(f[2], 16)))
            best = (metric, f[0], None if gw == "0.0.0.0" else gw)  # noqa: S104
    if best is None:
        raise NetInfoError(
            "No default route found; you may not be connected to a network.",
            "Connect to Wi-Fi or Ethernet and try again.",
        )
    return best[1], best[2]


def detect(run: CommandRunner = _run_ip, read_file: FileReader = _read_file) -> NetInfo:
    """Detect interface, IP, gateway and subnet. Raises :class:`NetInfoError`."""
    try:
        routes = json.loads(run(["-j", "route", "show"]) or "[]")
    except (FileNotFoundError, OSError, subprocess.SubprocessError, ValueError):
        routes = None
    if routes is not None:
        ifname, gateway = parse_default_route(routes)
        try:
            addrs = json.loads(run(["-j", "addr", "show", "dev", ifname]) or "[]")
        except (OSError, subprocess.SubprocessError, ValueError) as exc:
            raise NetInfoError(f"Could not read addresses for {ifname}.") from exc
        ip, subnet = parse_interface_addr(addrs, ifname)
        return NetInfo(ifname, ip, gateway, subnet)
    try:
        text = read_file("/proc/net/route")
    except OSError as exc:
        raise NetInfoError(
            "Could not read network information.",
            "Install iproute2: sudo apt install iproute2",
        ) from exc
    ifname, gateway = parse_proc_route(text)
    return NetInfo(ifname, None, gateway, None)

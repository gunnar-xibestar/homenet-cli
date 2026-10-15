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
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from homenet.core.commands import Command, run_command
from homenet.core.wsl import wsl_nat_active

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
    # True when WSL 2 NAT means scans see the virtual network, not the home LAN.
    wsl_nat: bool = False


ROUTE_ARGS = ("-j", "route", "show")
ADDR_ARGS = ("-j", "addr", "show")
WHOAMI_IP_ARGS = (ROUTE_ARGS, ADDR_ARGS)
_IP_PURPOSE = {
    "route": "read the routing table (default route and gateway)",
    "addr": "read interface addresses (IP and subnet)",
}


def build_ip_command(args: Sequence[str]) -> Command:
    """The single source of every ``ip`` Command."""
    args = tuple(args)
    sub = args[1] if len(args) > 1 else ""
    return Command(("ip", *args), _IP_PURPOSE.get(sub, "read network settings"))


def _run_ip(args: Sequence[str], timeout: float = 5.0) -> str:
    """Default ip runner: executes exactly ``build_ip_command(args).argv``."""
    cmd = build_ip_command(args)
    if shutil.which("ip") is None:
        raise FileNotFoundError("ip")
    proc = run_command(cmd, timeout)
    if proc.returncode != 0:
        raise subprocess.CalledProcessError(proc.returncode, list(cmd.argv), proc.stdout)
    return proc.stdout


def _read_file(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


_NO_ROUTE = (
    "No default route found; you may not be connected to a network.",
    "Connect to Wi-Fi or Ethernet and try again.",
)


def _metric(route: dict) -> int:
    m = route.get("metric")
    return m if isinstance(m, int) and not isinstance(m, bool) else 0


def parse_default_route(routes: object) -> tuple[str, str | None]:
    """Return (interface, gateway) of the lowest-metric default route.

    Malformed ``ip -j route`` output raises :class:`NetInfoError`, never a raw error.
    """
    if not isinstance(routes, list):
        raise NetInfoError("Unexpected output from `ip -j route` (expected a list).")
    defaults = [
        r
        for r in routes
        if isinstance(r, dict)
        and r.get("dst") == "default"
        and isinstance(r.get("dev"), str)
        and r["dev"]
    ]
    if not defaults:
        raise NetInfoError(*_NO_ROUTE)
    best = min(defaults, key=_metric)
    gateway = best.get("gateway")
    return best["dev"], gateway if isinstance(gateway, str) and gateway else None


def parse_interface_addr(addrs: object, ifname: str) -> tuple[str | None, str | None]:
    """Return (ip, subnet) for the interface's first IPv4 address (None, None if absent)."""
    if not isinstance(addrs, list):
        raise NetInfoError("Unexpected output from `ip -j addr` (expected a list).")
    for iface in addrs:
        if not isinstance(iface, dict) or iface.get("ifname") != ifname:
            continue
        info = iface.get("addr_info")
        for a in info if isinstance(info, list) else []:
            if not isinstance(a, dict) or a.get("family") != "inet" or not a.get("local"):
                continue
            try:
                net = ipaddress.ip_interface(f"{a['local']}/{a.get('prefixlen', 32)}").network
            except (ValueError, TypeError):
                continue
            return str(a["local"]), str(net)
    return None, None


def _hex_ip(value: str) -> str:
    return socket.inet_ntoa(struct.pack("<L", int(value, 16)))


def parse_proc_route(text: str) -> tuple[str, str | None, str | None]:
    """Parse /proc/net/route (little-endian hex) into (interface, gateway, subnet).

    The subnet comes from the interface's on-link route (Destination + Mask).
    """
    rows = []
    for line in text.splitlines()[1:]:
        f = line.split()
        if len(f) < 8:
            continue
        try:
            rows.append((f[0], _hex_ip(f[1]), _hex_ip(f[2]), int(f[6]), _hex_ip(f[7])))
        except (ValueError, struct.error):
            continue
    defaults = [r for r in rows if r[1] == "0.0.0.0"]  # noqa: S104
    if not defaults:
        raise NetInfoError(*_NO_ROUTE)
    ifname, _, gw, _, _ = min(defaults, key=lambda r: r[3])
    subnet = None
    for name, dest, _gw, _m, mask in sorted(rows, key=lambda r: r[3]):
        if name == ifname and dest != "0.0.0.0":  # noqa: S104
            try:
                subnet = str(ipaddress.ip_network(f"{dest}/{mask}"))
            except ValueError:
                continue
            break
    return ifname, None if gw == "0.0.0.0" else gw, subnet  # noqa: S104


def detect(
    run: CommandRunner = _run_ip,
    read_file: FileReader = _read_file,
    environ: Mapping[str, str] | None = None,
) -> NetInfo:
    """Detect interface, IP, gateway and subnet. Raises :class:`NetInfoError`.

    ``wsl_nat`` is true when this is WSL and the active address is in 172.16.0.0/12.
    """
    ip_ok = True
    try:
        routes = json.loads(run(list(ROUTE_ARGS)) or "[]")
    except (OSError, subprocess.SubprocessError, ValueError):
        ip_ok = False
    if ip_ok:
        ifname, gateway = parse_default_route(routes)
        try:
            addrs = json.loads(run(list(ADDR_ARGS)) or "[]")  # filtered by ifname below
        except (OSError, subprocess.SubprocessError, ValueError) as exc:
            raise NetInfoError(f"Could not read addresses for {ifname}.") from exc
        ip, subnet = parse_interface_addr(addrs, ifname)
        return _with_wsl(NetInfo(ifname, ip, gateway, subnet), environ, read_file)
    try:
        text = read_file("/proc/net/route")
    except OSError as exc:
        raise NetInfoError(
            "Could not read network information.",
            "Install iproute2: sudo apt install iproute2",
        ) from exc
    ifname, gateway, subnet = parse_proc_route(text)
    return _with_wsl(NetInfo(ifname, None, gateway, subnet), environ, read_file)


def _with_wsl(info: NetInfo, environ: Mapping[str, str] | None, read_file: FileReader) -> NetInfo:
    """Copy ``info`` with ``wsl_nat`` set. Does not read files unless the address matches."""
    if not wsl_nat_active(info.ip, info.subnet, environ=environ, read_text=read_file):
        return info
    return NetInfo(info.interface, info.ip, info.gateway, info.subnet, wsl_nat=True)

"""Device discovery: ping sweep of the local network plus name lookup.

Uses :mod:`runner` + :mod:`parser`. Names come from nmap's PTR result, then
reverse DNS, then mDNS via ``avahi-resolve`` when it is installed (skipped
quietly when it is not). All I/O is injectable. Never prints or exits.
"""

from __future__ import annotations

import dataclasses
import ipaddress
import shutil
import socket
import subprocess  # noqa: S404 - argument lists only
from collections.abc import Callable, Sequence

from homenet.core.parser import Device, parse_nmap_xml
from homenet.core.runner import DEFAULT_TIMEOUT, ScanResult, run_scan

ScanFn = Callable[..., ScanResult]
Resolver = Callable[[str], "str | None"]

MDNS_TIMEOUT = 2.0


def reverse_dns(ip: str, lookup: Callable[[str], tuple] | None = None) -> str | None:
    """Return the PTR name for ``ip`` or None. Never raises for lookup failures."""
    try:
        name = (lookup or socket.gethostbyaddr)(ip)[0]
    except (OSError, UnicodeError, IndexError, TypeError):
        return None
    return name or None


def _run_avahi(args: Sequence[str]) -> str:
    proc = subprocess.run(  # noqa: S603 - fixed argument list, validated IP
        list(args), capture_output=True, text=True, timeout=MDNS_TIMEOUT, check=False
    )
    return proc.stdout if proc.returncode == 0 else ""


def mdns_name(
    ip: str,
    which: Callable[[str], str | None] | None = None,
    run: Callable[[Sequence[str]], str] | None = None,
) -> str | None:
    """Resolve ``ip`` via ``avahi-resolve -a``; None if avahi is missing or fails."""
    try:
        ip = str(ipaddress.ip_address(ip))
    except ValueError:
        return None
    path = (which or shutil.which)("avahi-resolve")
    if path is None:
        return None
    try:
        out = (run or _run_avahi)([path, "-a", ip])
    except (OSError, subprocess.SubprocessError):
        return None
    for line in (out or "").splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == ip:
            return parts[1].rstrip(".")
    return None


def resolve_name(
    ip: str,
    reverse: Resolver | None = None,
    mdns: Resolver | None = None,
) -> str | None:
    """Best-effort hostname: reverse DNS first, then mDNS."""
    return (reverse or reverse_dns)(ip) or (mdns or mdns_name)(ip)


def sweep(
    local_network: ipaddress.IPv4Network | str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    resolve_names: bool = True,
    scan: ScanFn | None = None,
    resolver: Resolver | None = None,
) -> list[Device]:
    """Run a ``-sn`` ping sweep of ``local_network`` and return its devices.

    Devices without a hostname from nmap get one from :func:`resolve_name`.
    Raises runner ``NmapError`` / parser ``ParseError`` subclasses.
    """
    net = str(ipaddress.ip_network(local_network, strict=False))
    result = (scan or run_scan)(net, "ping", local_network=net, timeout=timeout)
    devices = parse_nmap_xml(result.xml)
    if not resolve_names:
        return devices
    resolve = resolver or resolve_name
    return [d if d.hostname else dataclasses.replace(d, hostname=resolve(d.ip)) for d in devices]


def normalize_mac(mac: str | None) -> str | None:
    """Lower-case colon form (``aa:bb:...``), or None."""
    if not mac:
        return None
    hexdigits = "".join(c for c in mac.lower() if c in "0123456789abcdef")
    if len(hexdigits) != 12:
        return mac.lower()
    return ":".join(hexdigits[i : i + 2] for i in range(0, 12, 2))


def find_device(
    devices: Sequence[Device], *, ip: str | None = None, mac: str | None = None
) -> Device | None:
    """Return the device matching ``mac`` (preferred) or ``ip``, else None."""
    if ip is None and mac is None:
        raise ValueError("Give an ip or a mac to look up.")
    want_mac = normalize_mac(mac)
    for d in devices:
        if want_mac and normalize_mac(d.mac) == want_mac:
            return d
    if ip is not None:
        for d in devices:
            if d.ip == ip:
                return d
    return None


def get_device(
    local_network: ipaddress.IPv4Network | str,
    *,
    ip: str | None = None,
    mac: str | None = None,
    **sweep_kwargs,
) -> Device | None:
    """Sweep ``local_network`` and return the single device with ``ip``/``mac``."""
    if ip is None and mac is None:
        raise ValueError("Give an ip or a mac to look up.")
    return find_device(sweep(local_network, **sweep_kwargs), ip=ip, mac=mac)

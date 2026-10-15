"""Device discovery: ping sweep of the local network plus name lookup.

Uses :mod:`runner` + :mod:`parser`. Names come from nmap's PTR result, then
reverse DNS, then mDNS via ``avahi-resolve`` when it is installed (skipped
quietly when it is not). All I/O is injectable. Never prints or exits.
"""

from __future__ import annotations

import dataclasses
import ipaddress
import json
import queue
import shutil
import socket
import subprocess  # noqa: S404 - argument lists only
import threading
import time
from collections.abc import Callable, Sequence

from homenet.core.netinfo import _run_ip
from homenet.core.parser import Device, parse_nmap_xml
from homenet.core.runner import (
    DEFAULT_TIMEOUT,
    ScanResult,
    TargetNotAllowedError,
    default_route_network,
    run_scan,
)

ScanFn = Callable[..., ScanResult]
Resolver = Callable[[str], "str | None"]

MDNS_TIMEOUT = 1.0  # per avahi-resolve call
RESOLVE_BUDGET = 5.0  # total seconds for all name lookups in one sweep
RESOLVE_WORKERS = 16


def reverse_dns(ip: str, lookup: Callable[[str], tuple] | None = None) -> str | None:
    """Return the PTR name for ``ip`` or None. Never raises for lookup failures."""
    try:
        name = (lookup or socket.gethostbyaddr)(ip)[0]
    except (OSError, UnicodeError, IndexError, TypeError):
        return None
    return name or None


def _run_avahi(args: Sequence[str], timeout: float = MDNS_TIMEOUT) -> str:
    proc = subprocess.run(  # noqa: S603 - fixed argument list, validated IP
        list(args), capture_output=True, text=True, timeout=timeout, check=False
    )
    return proc.stdout if proc.returncode == 0 else ""


def mdns_name(
    ip: str,
    which: Callable[[str], str | None] | None = None,
    run: Callable[[Sequence[str]], str] | None = None,
    timeout: float = MDNS_TIMEOUT,
) -> str | None:
    """Resolve ``ip`` via ``avahi-resolve -a`` (bounded by ``timeout``).

    Returns None if avahi is missing, times out or fails.
    """
    try:
        ip = str(ipaddress.ip_address(ip))
    except ValueError:
        return None
    path = (which or shutil.which)("avahi-resolve")
    if path is None:
        return None
    try:
        out = run([path, "-a", ip]) if run else _run_avahi([path, "-a", ip], timeout)
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


def resolve_all(
    ips: Sequence[str],
    resolver: Resolver | None = None,
    *,
    budget: float = RESOLVE_BUDGET,
    max_workers: int = RESOLVE_WORKERS,
) -> dict[str, str | None]:
    """Resolve ``ips`` concurrently within an overall ``budget`` in seconds.

    Lookups still running when the budget runs out are abandoned and map to None.
    Workers are daemon threads, so a hung lookup blocks neither the caller nor
    process exit.
    """
    resolve = resolver or resolve_name
    names: dict[str, str | None] = dict.fromkeys(ips)
    if not ips:
        return names
    deadline = time.monotonic() + max(0.0, budget)
    work: queue.SimpleQueue[str] = queue.SimpleQueue()
    for ip in names:
        work.put(ip)
    results: queue.SimpleQueue[tuple[str, str | None]] = queue.SimpleQueue()

    def worker() -> None:
        while time.monotonic() < deadline:
            try:
                ip = work.get_nowait()
            except queue.Empty:
                return
            try:
                name = resolve(ip)
            except Exception:  # noqa: BLE001 - a failed lookup just means "no name"
                name = None
            results.put((ip, name))

    # Daemon threads: a lookup stuck in gethostbyaddr can never block process exit.
    for i in range(max(1, min(max_workers, len(names)))):
        threading.Thread(target=worker, name=f"homenet-resolve-{i}", daemon=True).start()
    pending = len(names)
    while pending:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            ip, name = results.get(timeout=remaining)
        except queue.Empty:
            break
        names[ip] = name
        pending -= 1
    return names


def detect_local_network(
    run: Callable[[Sequence[str]], str] | None = None,
) -> ipaddress.IPv4Network | None:
    """Subnet of the default-route interface (via ``ip -j``), or None if unknown."""
    run = run or _run_ip
    try:
        routes = json.loads(run(["-j", "route", "show"]) or "null")
        addrs = json.loads(run(["-j", "addr", "show"]) or "null")
    except (OSError, subprocess.SubprocessError, ValueError):
        return None
    return default_route_network(routes, addrs)


def sweep(
    target: ipaddress.IPv4Network | str | None = None,
    *,
    local_network: ipaddress.IPv4Network | str | None = None,
    force: bool = False,
    timeout: float = DEFAULT_TIMEOUT,
    resolve_names: bool = True,
    resolve_budget: float = RESOLVE_BUDGET,
    scan: ScanFn | None = None,
    resolver: Resolver | None = None,
    ip_runner: Callable[[Sequence[str]], str] | None = None,
) -> list[Device]:
    """Run a ``-sn`` ping sweep and return the devices found.

    ``local_network`` defaults to the default-route subnet from
    :func:`detect_local_network` (inject it in tests). ``target`` defaults to
    that subnet; a target outside it is refused by the runner unless ``force``.
    Hostnames missing from nmap are looked up concurrently within
    ``resolve_budget`` seconds. Raises runner ``NmapError`` / ``ParseError``.
    """
    local = local_network if local_network is not None else detect_local_network(ip_runner)
    if target is None:
        target = local
    if target is None:
        raise TargetNotAllowedError(
            "Could not detect your local network.",
            "Check you are connected (see `homenet whoami-net`) or give a subnet to scan.",
        )
    net = str(ipaddress.ip_network(target, strict=False))
    local_str = str(ipaddress.ip_network(local, strict=False)) if local is not None else None
    result = (scan or run_scan)(net, "ping", local_network=local_str, force=force, timeout=timeout)
    devices = parse_nmap_xml(result.xml)
    if not resolve_names:
        return devices
    names = resolve_all([d.ip for d in devices if not d.hostname], resolver, budget=resolve_budget)
    return [d if d.hostname else dataclasses.replace(d, hostname=names.get(d.ip)) for d in devices]


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
    target: ipaddress.IPv4Network | str | None = None,
    *,
    ip: str | None = None,
    mac: str | None = None,
    **sweep_kwargs,
) -> Device | None:
    """Sweep ``target`` (default: local network) and return the device with ``ip``/``mac``."""
    if ip is None and mac is None:
        raise ValueError("Give an ip or a mac to look up.")
    return find_device(sweep(target, **sweep_kwargs), ip=ip, mac=mac)

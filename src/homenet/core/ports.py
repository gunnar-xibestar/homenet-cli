"""Top-ports and light service scans of one host or the local subnet.

Targets must lie inside the default-route subnet (:func:`default_route_network`);
there is no force override here. Never prints or exits.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable, Sequence

from homenet.core.devices import detect_local_network
from homenet.core.parser import Device, parse_nmap_xml
from homenet.core.runner import (
    DEFAULT_TIMEOUT,
    InvalidTargetError,
    ScanResult,
    TargetNotAllowedError,
    run_scan,
)

ScanFn = Callable[..., ScanResult]
DEFAULT_TOP_PORTS = 100


def resolve_local_target(
    target: ipaddress.IPv4Network | str | None,
    local_network: ipaddress.IPv4Network | str | None = None,
    ip_runner: Callable[[Sequence[str]], str] | None = None,
) -> tuple[str, str]:
    """Return (target, local_network) as strings, refusing anything outside the local subnet.

    ``target`` defaults to the whole local subnet. ``local_network`` defaults to
    the default-route subnet detected via ``ip -j``.
    """
    local = local_network if local_network is not None else detect_local_network(ip_runner)
    if local is None:
        raise TargetNotAllowedError(
            "Could not detect your local network.",
            "Check you are connected (see `homenet whoami-net`).",
        )
    local_net = ipaddress.ip_network(local, strict=False)
    try:
        net = ipaddress.ip_network(target if target is not None else local_net, strict=False)
    except ValueError as exc:
        raise InvalidTargetError(
            f"{target!r} is not a valid IP address or subnet.",
            "Use an IP like 192.168.1.10 or your subnet like 192.168.1.0/24.",
        ) from exc
    if net.version != 4 or not net.subnet_of(local_net):
        raise TargetNotAllowedError(
            f"{net} is outside your local subnet ({local_net}).",
            "Only devices on your own network can be scanned.",
        )
    return str(net), str(local_net)


def _scan(mode, target, top_ports, local_network, timeout, scan, ip_runner) -> list[Device]:
    net, local = resolve_local_target(target, local_network, ip_runner)
    result = (scan or run_scan)(
        net, mode, top_ports, local_network=local, force=False, timeout=timeout
    )
    return parse_nmap_xml(result.xml)


def scan_ports(
    target: ipaddress.IPv4Network | str | None = None,
    *,
    top_ports: int = DEFAULT_TOP_PORTS,
    local_network: ipaddress.IPv4Network | str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    scan: ScanFn | None = None,
    ip_runner: Callable[[Sequence[str]], str] | None = None,
) -> list[Device]:
    """TCP-connect scan (``-sT --top-ports N``) of one host or the local subnet."""
    return _scan("tcp-connect", target, top_ports, local_network, timeout, scan, ip_runner)


def scan_services(
    target: ipaddress.IPv4Network | str | None = None,
    *,
    top_ports: int = DEFAULT_TOP_PORTS,
    local_network: ipaddress.IPv4Network | str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    scan: ScanFn | None = None,
    ip_runner: Callable[[Sequence[str]], str] | None = None,
    allow_subnet: bool = False,
) -> list[Device]:
    """Light service detection (``-sT -sV --version-light --top-ports N``).

    Never uses scripts, ``-A`` or ``-O``. Port.product / Port.version are filled in.
    Only a single host is scanned unless ``allow_subnet=True``.
    """
    net, local = resolve_local_target(target, local_network, ip_runner)  # local-only first
    if not allow_subnet and (target is None or ipaddress.ip_network(net).num_addresses != 1):
        raise InvalidTargetError(
            f"{net} is a subnet; service detection only scans one device by default.",
            "Give one IP, e.g. 192.168.1.10, or explicitly allow a subnet scan.",
        )
    return _scan("service", net, top_ports, local, timeout, scan, ip_runner)

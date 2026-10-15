"""Detect WSL and the WSL 2 NAT range. Never prints.

I/O goes through injectable callables so tests can pass fakes.
"""

from __future__ import annotations

import ipaddress
import os
from collections.abc import Callable, Mapping
from pathlib import Path

# WSL 2's default NAT places the distro inside this range.
WSL_NAT = ipaddress.ip_network("172.16.0.0/12")

WSL_NAT_FIX = (
    "Set networkingMode=mirrored under [wsl2] in %UserProfile%\\.wslconfig, "
    "then run `wsl --shutdown`."
)


def _read_text(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def is_wsl(
    environ: Mapping[str, str] | None = None,
    read_text: Callable[[str], str] | None = None,
) -> bool:
    """True when this process looks like a WSL distro.

    ``WSL_DISTRO_NAME`` (non-empty) is enough. Otherwise ``microsoft`` anywhere
    in ``/proc/version`` counts, in any case. A missing file is not WSL.
    """
    env = os.environ if environ is None else environ
    if (env.get("WSL_DISTRO_NAME") or "").strip():
        return True
    try:
        version = (read_text or _read_text)("/proc/version")
    except OSError:
        return False
    return "microsoft" in version.lower()


def in_wsl_nat(address: str | None) -> bool:
    """True when an IPv4 address or subnet sits inside 172.16.0.0/12."""
    if not address or not str(address).strip():
        return False
    text = str(address).strip()
    try:
        if "/" in text:
            network = ipaddress.ip_network(text, strict=False)
        else:
            network = ipaddress.ip_network(f"{text}/32")
    except ValueError:
        return False
    return network.version == 4 and network.subnet_of(WSL_NAT)


def wsl_nat_active(
    *addresses: str | None,
    environ: Mapping[str, str] | None = None,
    read_text: Callable[[str], str] | None = None,
) -> bool:
    """True when this is WSL and an address is in the WSL 2 NAT range.

    Addresses outside that range return False without reading ``/proc/version``.
    """
    if not any(in_wsl_nat(item) for item in addresses):
        return False
    return is_wsl(environ, read_text)


def wsl_nat_detail(network: str | None = None) -> str:
    """Warning that scans see the WSL virtual network, not the home LAN."""
    if network:
        return (
            f"Active network {network} is the WSL virtual network, not your home LAN. "
            "Scans see that virtual network, not the home LAN."
        )
    return "Scans see the WSL virtual network, not the home LAN."

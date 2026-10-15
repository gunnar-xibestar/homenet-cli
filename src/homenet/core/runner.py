"""Safe nmap runner.

Commands are built as argument lists (never ``shell=True``), only allowlisted,
non-intrusive scan modes are permitted, targets are validated before they ever
reach nmap, and every failure is raised as a typed :class:`NmapError` subclass.
This module never prints and never calls ``sys.exit``.
"""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import subprocess  # noqa: S404 - used with argument lists only
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from homenet.core.commands import Command, run_command

DEFAULT_TIMEOUT = 120.0
MAX_PREFIX_LEN = 16  # refuse ranges larger than a /16
MAX_TOP_PORTS = 1000

_ALLOWED_RANGES = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
)

# Scan modes: name -> fixed nmap flags. Port scans must be chosen explicitly.
SCAN_MODES: dict[str, tuple[str, ...]] = {
    "ping": ("-sn",),
    "tcp-connect": ("-sT",),
    "syn": ("-sS",),
    # Service detection: -sV is only ever allowed with --version-light (intensity 2).
    "service": ("-sT", "-sV", "--version-light"),
}
DEFAULT_MODE = "ping"
PORT_SCAN_MODES = frozenset({"tcp-connect", "syn", "service"})
# Modes that need raw sockets (root or CAP_NET_RAW); checked before nmap runs.
PRIVILEGED_MODES = frozenset({"syn"})
CAP_NET_RAW = 13

# Every flag that may ever appear in a command we build.
ALLOWED_FLAGS = frozenset(
    {
        "-sn",
        "-sT",
        "-sS",
        "-sV",
        "--version-light",
        "--top-ports",
        "-oX",
        "-n",
        "-T3",
        "-T4",
        "--privileged",
    }
)

# Explicitly intrusive options, rejected with a clear message.
BLOCKED_FLAGS = frozenset(
    {
        "-sC",
        "-A",
        "-O",
        "--script",
        "--script-args",
        "-sU",
        "-p-",
        "-p",
        "--osscan-guess",
        "--version-all",
        "--version-intensity",
        "--version-trace",
        "-T5",
        "-iL",
        "-oN",
        "-oG",
        "-oA",
        "--datadir",
        "--resume",
    }
)


class NmapError(Exception):
    """Base class for all runner errors. ``hint`` is a beginner-friendly fix."""

    def __init__(self, message: str, hint: str | None = None) -> None:
        super().__init__(message)
        self.hint = hint


class NmapNotFoundError(NmapError):
    pass


class InvalidTargetError(NmapError):
    pass


class TargetNotAllowedError(NmapError):
    pass


class DisallowedFlagError(NmapError):
    pass


class NmapTimeoutError(NmapError):
    pass


class NmapPermissionError(NmapError):
    pass


class NmapFailedError(NmapError):
    def __init__(self, message: str, returncode: int, stderr: str, hint: str | None = None):
        super().__init__(message, hint)
        self.returncode = returncode
        self.stderr = stderr


@dataclass(frozen=True)
class ScanResult:
    args: tuple[str, ...]
    xml: str
    stderr: str
    returncode: int


def validate_target(
    target: str,
    local_network: ipaddress.IPv4Network | str | None = None,
    force: bool = False,
) -> ipaddress.IPv4Network:
    """Return the target as a network or raise.

    Always refused (even with ``force``): malformed input, non-IPv4, public
    ranges, and ranges larger than /16. Without ``force`` the target must also
    lie within ``local_network``: the subnet of the default-route interface only
    (see :func:`default_route_network`), never docker0 or other bridges.
    """
    text = (target or "").strip()
    if not text or text.startswith("-") or any(c.isspace() for c in text):
        raise InvalidTargetError(
            f"{target!r} is not a valid target.",
            "Use an IP address or subnet like 192.168.1.0/24.",
        )
    try:
        net = ipaddress.ip_network(text, strict=False)
    except ValueError as exc:
        raise InvalidTargetError(
            f"{target!r} is not a valid IP address or subnet.",
            "Use an IP address or subnet like 192.168.1.0/24.",
        ) from exc
    if net.version != 4:
        raise InvalidTargetError(f"{target!r}: only IPv4 targets are supported.")
    if not any(net.subnet_of(r) for r in _ALLOWED_RANGES):
        raise TargetNotAllowedError(
            f"{net} is not a private home-network range; scanning it is refused.",
            "Only 10.x, 172.16-31.x, 192.168.x (and link-local/loopback) can be scanned.",
        )
    if net.prefixlen < MAX_PREFIX_LEN:
        raise TargetNotAllowedError(
            f"{net} is too large to scan (more than a /{MAX_PREFIX_LEN}).",
            "Pick a smaller range, e.g. your own /24 subnet.",
        )
    if not force:
        local = ipaddress.ip_network(local_network, strict=False) if local_network else None
        if local is None or local.version != 4 or not net.subnet_of(local):
            raise TargetNotAllowedError(
                f"{net} is outside your local subnet ({local or 'none detected'}).",
                "Scan your own subnet (see `homenet whoami-net`) or pass --force if you "
                "own that network.",
            )
    return net


def default_route_network(routes: object, addrs: object) -> ipaddress.IPv4Network | None:
    """Return the IPv4 subnet of the default-route interface from ``ip -j`` data.

    Only the interface carrying the lowest-metric default route counts as
    local; docker0, virbr0 and other bridges are deliberately ignored.
    """
    if not isinstance(routes, list) or not isinstance(addrs, list):
        return None
    defaults = [
        r
        for r in routes
        if isinstance(r, dict) and r.get("dst") == "default" and isinstance(r.get("dev"), str)
    ]
    if not defaults:
        return None
    dev = min(defaults, key=lambda r: r.get("metric") if isinstance(r.get("metric"), int) else 0)[
        "dev"
    ]
    for iface in addrs:
        if not isinstance(iface, dict) or iface.get("ifname") != dev:
            continue
        for a in iface.get("addr_info") or []:
            if isinstance(a, dict) and a.get("family") == "inet" and a.get("local"):
                try:
                    return ipaddress.ip_interface(f"{a['local']}/{a.get('prefixlen', 32)}").network
                except ValueError:
                    return None
    return None


def _read_text(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def has_raw_socket_privileges(
    geteuid: Callable[[], int] | None = None, read_text: Callable[[str], str] | None = None
) -> bool:
    """True when running as root or with CAP_NET_RAW in the effective set."""
    if (geteuid or os.geteuid)() == 0:
        return True
    try:
        status = (read_text or _read_text)("/proc/self/status")
    except OSError:
        return False
    m = re.search(r"^CapEff:\s*([0-9a-fA-F]+)", status, re.MULTILINE)
    return bool(m and int(m.group(1), 16) & (1 << CAP_NET_RAW))


def check_flags(flags: Sequence[str]) -> None:
    """Raise :class:`DisallowedFlagError` unless every flag is allowlisted.

    ``-sV`` is only accepted together with ``--version-light``.
    """
    bases = [f.split("=", 1)[0] for f in flags]
    if "-sV" in bases and "--version-light" not in bases:
        raise DisallowedFlagError(
            "nmap option '-sV' is only allowed together with --version-light.",
            "homenet only runs light service detection.",
        )
    for flag in flags:
        base = flag.split("=", 1)[0]
        if (
            base in BLOCKED_FLAGS
            or base.startswith("--script")
            or (base.startswith("--version-") and base != "--version-light")
            or (base.startswith("-p") and base not in ALLOWED_FLAGS)
        ):
            raise DisallowedFlagError(
                f"nmap option {flag!r} is intrusive and is not allowed.",
                "homenet only runs discovery and basic top-port scans.",
            )
        if base not in ALLOWED_FLAGS:
            raise DisallowedFlagError(f"nmap option {flag!r} is not on the allowlist.")


def build_args(
    target: str,
    mode: str = DEFAULT_MODE,
    top_ports: int = 100,
    *,
    local_network: ipaddress.IPv4Network | str | None = None,
    force: bool = False,
    nmap_path: str = "nmap",
    privileged: bool = False,
) -> list[str]:
    """Build the nmap argument list. Pure: runs nothing."""
    if mode not in SCAN_MODES:
        raise DisallowedFlagError(
            f"Unknown scan mode {mode!r}.", f"Choose one of: {', '.join(SCAN_MODES)}."
        )
    net = validate_target(target, local_network, force)
    flags: list[str] = list(SCAN_MODES[mode])
    if mode in PORT_SCAN_MODES:
        if (
            not isinstance(top_ports, int)
            or isinstance(top_ports, bool)
            or not (1 <= top_ports <= MAX_TOP_PORTS)
        ):
            raise DisallowedFlagError(f"top_ports must be between 1 and {MAX_TOP_PORTS}.")
        flags += ["--top-ports", str(top_ports)]
    if privileged:
        flags.append("--privileged")  # caps without root: tell nmap to use raw sockets
    flags += ["-T4", "-oX", "-"]
    check_flags([f for f in flags if not f.isdigit() and f != "-"])
    return [nmap_path, *flags, str(net)]


def privileged_for(
    mode: str,
    geteuid: Callable[[], int] | None = None,
    read_text: Callable[[str], str] | None = None,
) -> bool:
    """Whether ``--privileged`` is needed; raises if ``mode`` needs root and we lack it."""
    if mode not in PRIVILEGED_MODES:
        return False
    if not has_raw_socket_privileges(geteuid, read_text):
        raise NmapPermissionError(
            f"The {mode!r} scan needs root privileges.",
            "Re-run with sudo, or use the default ping or tcp-connect mode.",
        )
    return (geteuid or os.geteuid)() != 0


def build_scan_command(
    target: str,
    mode: str = DEFAULT_MODE,
    top_ports: int = 100,
    *,
    local_network: ipaddress.IPv4Network | str | None = None,
    force: bool = False,
    privileged: bool = False,
    nmap_path: str | None = None,
) -> Command:
    """The single source of the nmap Command (validated; runs nothing)."""
    args = build_args(
        target,
        mode,
        top_ports,
        local_network=local_network,
        force=force,
        nmap_path=nmap_path or shutil.which("nmap") or "nmap",
        privileged=privileged,
    )
    purpose = {
        "ping": "find devices that are up (ping sweep)",
        "tcp-connect": f"check the top {top_ports} TCP ports",
        "syn": f"check the top {top_ports} TCP ports (SYN scan)",
        "service": f"identify services on the top {top_ports} ports (light)",
    }[mode]
    return Command(tuple(args), purpose)


def run_scan(
    target: str,
    mode: str = DEFAULT_MODE,
    top_ports: int = 100,
    *,
    local_network: ipaddress.IPv4Network | str | None = None,
    force: bool = False,
    timeout: float = DEFAULT_TIMEOUT,
    geteuid: Callable[[], int] | None = None,
    read_text: Callable[[str], str] | None = None,
) -> ScanResult:
    """Validate, run nmap and return its XML output. Raises NmapError subclasses.

    Runs exactly ``build_scan_command(...).argv``; the command hook sees it first.
    """
    privileged = privileged_for(mode, geteuid, read_text)
    nmap = shutil.which("nmap")
    # Validate before checking for nmap so bad targets are always refused first.
    cmd = build_scan_command(
        target,
        mode,
        top_ports,
        local_network=local_network,
        force=force,
        privileged=privileged,
        nmap_path=nmap or "nmap",
    )
    if nmap is None:
        raise NmapNotFoundError("nmap is not installed.", "Try: sudo apt install nmap")
    try:
        proc = run_command(cmd, timeout)
    except subprocess.TimeoutExpired as exc:
        raise NmapTimeoutError(
            f"nmap did not finish within {timeout:g} seconds.",
            "Try a smaller range or a longer timeout.",
        ) from exc
    except FileNotFoundError as exc:
        raise NmapNotFoundError("nmap is not installed.", "Try: sudo apt install nmap") from exc
    except PermissionError as exc:
        raise NmapPermissionError("Permission denied running nmap.") from exc
    stderr = proc.stderr or ""
    if proc.returncode != 0:
        raise NmapFailedError(
            f"nmap exited with code {proc.returncode}.", proc.returncode, stderr.strip()
        )
    return ScanResult(cmd.argv, proc.stdout or "", stderr, proc.returncode)

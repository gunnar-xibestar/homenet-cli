"""Beginner-friendly command line for home network detection.

``doctor`` asks :mod:`homenet.core.checks` for results and prints them.
``whoami-net`` asks :mod:`homenet.core.netinfo` and prints them.
``devices``, ``device``, ``baseline``, and ``new-devices`` ask
:mod:`homenet.core.devices` and :mod:`homenet.core.baseline`.
The home network they scan comes from :func:`homenet.core.netinfo.detect`.
This module does not spawn system commands itself. Core does.

``new-devices`` exits 0 when the live scan matches the saved snapshot,
1 when a device is new, missing, changed, or has a different MAC address,
and 2 when the command fails.
``--json`` prints the shapes documented in :mod:`homenet.output` to stdout,
with no banner. Errors go to stderr as a JSON object with ``error`` and
``fix_hint``.
"""

from __future__ import annotations

import argparse
import ipaddress
import sys
from collections.abc import Sequence
from dataclasses import dataclass

from homenet.core import baseline, checks, devices, netinfo
from homenet.core.baseline import BaselineError
from homenet.core.checks import CheckResult
from homenet.core.parser import Device, ParseError
from homenet.core.runner import NmapError
from homenet.output import (
    _clean,
    format_device,
    format_device_json,
    format_devices,
    format_devices_json,
    format_diff,
    format_diff_json,
    format_doctor_json,
    format_error,
    format_error_json,
    format_whoami,
    format_whoami_json,
)

BANNER = "Only scan networks you own or have permission to scan."


class _HelpFormatter(argparse.RawDescriptionHelpFormatter):
    """Keep each command and its summary on one line in the top-level help."""

    def __init__(self, prog: str) -> None:
        super().__init__(prog, max_help_position=40, width=88)

    def add_argument(self, action: argparse.Action) -> None:
        if action.help is argparse.SUPPRESS:
            return
        invocations = [self._format_action_invocation(action)]
        for subaction in self._iter_indented_subactions(action):
            invocations.append(self._format_action_invocation(subaction))
        # Subcommands are indented again when printed. Reserve that space so
        # longer names such as "whoami-net" stay next to their summary.
        action_length = max(map(len, invocations)) + self._current_indent
        action_length += self._indent_increment
        self._action_max_length = max(self._action_max_length, action_length)
        self._add_item(self._format_action, [action])


_NOT_IMPLEMENTED_EXIT = 1
_NAME_WIDTH = 12


@dataclass(frozen=True)
class _Command:
    name: str
    summary: str
    description: str
    example: str
    scan: bool = False
    ip: bool = False
    json: bool = False


_COMMANDS: tuple[_Command, ...] = (
    _Command(
        "whoami-net",
        "Show this computer's address on your home network",
        "Show this computer's IP address, the interface it is using, "
        "and the home network it belongs to.",
        "homenet whoami-net",
        scan=True,
        json=True,
    ),
    _Command(
        "devices",
        "List devices currently on your home network",
        "Look for computers, phones, printers, and other devices on your "
        "home network and print a simple list.",
        "homenet devices",
        scan=True,
        json=True,
    ),
    _Command(
        "device",
        "Show details for one device by its IP address",
        "Show what we know about a single device. Use the IP address you "
        "saw from `homenet devices`.",
        "homenet device 192.168.1.20",
        scan=True,
        ip=True,
        json=True,
    ),
    _Command(
        "ports",
        "List open ports on one device",
        "List the open ports on one device. An open port is a door a program "
        "is listening on, such as a website or a printer.",
        "homenet ports 192.168.1.1",
        scan=True,
        ip=True,
    ),
    _Command(
        "services",
        "Show the services running on one device",
        "Name the services running on one device, such as a web server or "
        "file sharing, when they can be identified.",
        "homenet services 192.168.1.1",
        scan=True,
        ip=True,
    ),
    _Command(
        "router",
        "Find your home router",
        "Find the router that connects your home network to the internet and show its address.",
        "homenet router",
        scan=True,
    ),
    _Command(
        "baseline",
        "Save a snapshot of the devices on your network",
        "Save a snapshot of the devices on your network right now. "
        "Later, `homenet new-devices` compares against this snapshot.",
        "homenet baseline",
        scan=True,
    ),
    _Command(
        "new-devices",
        "List devices that were not in your saved snapshot",
        "Compare the devices on your network now with the snapshot from "
        "`homenet baseline`, and list anything new.\n"
        "\n"
        "Exit status is 0 when nothing changed, 1 when a device is new, "
        "missing, changed, or has a different MAC address, and 2 on error.",
        "homenet new-devices",
        scan=True,
        json=True,
    ),
    _Command(
        "speed",
        "Check how fast your internet connection is",
        "Measure how fast your connection to the internet is, in plain numbers.",
        "homenet speed",
    ),
    _Command(
        "doctor",
        "Check that tools and permissions are ready",
        "Check that nmap, the ip command, and ping are installed, that you are allowed "
        "to scan, and that this computer has a network route. Run this first if a scan fails.",
        "homenet doctor",
        json=True,
    ),
)


def _description(spec: _Command) -> str:
    if spec.scan:
        return f"{spec.description}\n\n{BANNER}"
    return spec.description


def _not_implemented(args: argparse.Namespace) -> int:
    if args.scan:
        print(BANNER)
        print()
    print(f"{args.command_name} is not implemented yet.")
    print(f"See what it will do with: homenet {args.command_name} --help")
    return _NOT_IMPLEMENTED_EXIT


def _label(result: CheckResult) -> str:
    if result.severity == "warning":
        return "WARN"
    if result.ok:
        return "PASS"
    return "FAIL"


def _is_error(result: CheckResult) -> bool:
    """An error-level check failed. Warnings are not failures."""
    return not result.ok and result.severity != "warning"


def _summary(results: list[CheckResult]) -> str:
    errors = sum(1 for result in results if _is_error(result))
    warnings = sum(1 for result in results if result.severity == "warning")
    if errors == 0 and warnings == 0:
        noun = "check" if len(results) == 1 else "checks"
        return f"All {len(results)} {noun} passed."
    parts: list[str] = []
    if errors:
        noun = "check" if errors == 1 else "checks"
        parts.append(f"{errors} {noun} failed.")
    else:
        parts.append("No errors.")
    if warnings:
        noun = "warning" if warnings == 1 else "warnings"
        parts.append(f"{warnings} {noun}.")
    return " ".join(parts)


def _format_doctor(results: list[CheckResult]) -> str:
    lines = ["Home network doctor", ""]
    for result in results:
        status = _label(result)
        # Details can repeat an interface or gateway from the network.
        detail = _clean(result.detail) or ""
        lines.append(f"{status}  {result.name:<{_NAME_WIDTH}} {detail}")
        if status != "PASS" and result.fix_hint:
            hint = _clean(result.fix_hint)
            if hint:
                lines.append(f"      Fix: {hint}")
    lines.append("")
    lines.append(_summary(results))
    return "\n".join(lines)


def _run_doctor(args: argparse.Namespace) -> int:
    results = checks.run_all_checks()
    if args.json:
        print(format_doctor_json(results))
    else:
        print(_format_doctor(results))
    return 1 if any(_is_error(result) for result in results) else 0


def _run_whoami(args: argparse.Namespace) -> int:
    try:
        info = netinfo.detect()
    except netinfo.NetInfoError as exc:
        return _fail(args, exc)
    if args.json:
        print(format_whoami_json(info))
    else:
        print(format_whoami(info))
    return 0


def _run_devices(args: argparse.Namespace) -> int:
    _begin_scan(args)
    found = _scan_home(args)
    if found is None:
        return 1
    if args.json:
        print(format_devices_json(found))
    else:
        print(format_devices(found))
    return 0


def _run_device(args: argparse.Namespace) -> int:
    _begin_scan(args)
    try:
        address = ipaddress.ip_address(args.ip.strip())
    except ValueError:
        return _fail_message(
            args,
            f"{args.ip} is not a valid IP address.",
            "Use an address from `homenet devices`, for example 192.168.1.20.",
        )
    if address.version != 4:
        return _fail_message(
            args,
            f"{args.ip} is not an IPv4 address.",
            "homenet looks up IPv4 addresses. Use one from `homenet devices`.",
        )
    ok, found = _lookup_home(args, str(address))
    if not ok:
        return 1
    if found is None:
        return _fail_message(
            args,
            f"No device was found at {address}.",
            "Run `homenet devices` to see which addresses answered.",
        )
    if args.json:
        print(format_device_json(found))
    else:
        print(format_device(found))
    return 0


def _run_baseline(args: argparse.Namespace) -> int:
    _begin_scan(args)
    found = _scan_home(args)
    if found is None:
        return 1
    try:
        path = baseline.save_baseline(found)
    except BaselineError as exc:
        return _fail(args, exc)
    count = len(found)
    noun = "device" if count == 1 else "devices"
    print(f"Saved {count} {noun} to {path}.")
    print("Compare later with `homenet new-devices`.")
    return 0


def _run_new_devices(args: argparse.Namespace) -> int:
    """Exit 0 when nothing changed, 1 when something changed, and 2 on error."""
    _begin_scan(args)
    try:
        saved = baseline.load_baseline()
    except BaselineError as exc:
        return _fail(args, exc, code=2)
    found = _scan_home(args)
    if found is None:
        return 2
    report = baseline.diff_devices(saved, found)
    if args.json:
        print(format_diff_json(report))
    else:
        print(format_diff(report))
    return 1 if report.has_changes else 0


def _begin_scan(args: argparse.Namespace) -> None:
    """Remind the user to scan only networks they own. JSON stays banner-free."""
    if getattr(args, "json", False):
        return
    print(BANNER)
    print()


def _home_network() -> str:
    """IPv4 subnet from netinfo, or raise :class:`NetInfoError` with a fix hint."""
    info = netinfo.detect()
    subnet = (info.subnet or "").strip()
    if not subnet:
        raise netinfo.NetInfoError(
            "Could not detect your home network.",
            "Connect to Wi-Fi or Ethernet, then try `homenet whoami-net`.",
        )
    try:
        network = ipaddress.ip_network(subnet, strict=False)
    except ValueError as exc:
        raise netinfo.NetInfoError(
            f"The detected home network {subnet!r} is not a valid subnet.",
            "Run `homenet whoami-net` and check the home network it shows.",
        ) from exc
    if network.version != 4:
        raise netinfo.NetInfoError(
            f"The detected home network {network} is not IPv4.",
            "homenet scans IPv4 home networks. Connect with IPv4 and try again.",
        )
    return str(network)


def _scan_home(args: argparse.Namespace) -> list[Device] | None:
    """Sweep the netinfo subnet. None means the error was already printed."""
    try:
        network = _home_network()
        return devices.sweep(network, local_network=network, resolve_names=True)
    except (netinfo.NetInfoError, NmapError, ParseError) as exc:
        _fail(args, exc)
        return None


def _lookup_home(args: argparse.Namespace, ip: str) -> tuple[bool, Device | None]:
    """Return ``(True, device)``. The device is None when that address did not answer.

    ``(False, None)`` means an error was already printed.
    """
    try:
        network = _home_network()
        return True, devices.get_device(network, ip=ip, local_network=network, resolve_names=True)
    except (netinfo.NetInfoError, NmapError, ParseError) as exc:
        _fail(args, exc)
        return False, None


def _fail(args: argparse.Namespace, exc: BaseException, code: int = 1) -> int:
    hint = getattr(exc, "hint", None)
    return _fail_message(args, str(exc), hint if isinstance(hint, str) else None, code)


def _fail_message(args: argparse.Namespace, message: str, hint: str | None, code: int = 1) -> int:
    """Beginner-friendly error. ``--json`` writes ``{"error", "fix_hint"}`` to stderr.

    ``code`` is 2 for ``new-devices`` failures and 1 for every other command.
    """
    if getattr(args, "json", False):
        print(format_error_json(message, hint), file=sys.stderr)
    else:
        print(format_error(message, hint))
    return code


_HANDLERS = {
    "doctor": _run_doctor,
    "whoami-net": _run_whoami,
    "devices": _run_devices,
    "device": _run_device,
    "baseline": _run_baseline,
    "new-devices": _run_new_devices,
}


def _add_command(subparsers, spec: _Command) -> None:
    parser = subparsers.add_parser(
        spec.name,
        help=spec.summary,
        description=_description(spec),
        epilog=f"Example:\n  {spec.example}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    if spec.ip:
        parser.add_argument(
            "ip",
            metavar="IP",
            help="IP address of the device, for example 192.168.1.20",
        )
    if spec.json:
        parser.add_argument(
            "--json",
            action="store_true",
            help="Print JSON to stdout, with no banner. Errors go to stderr as JSON.",
        )
    handler = _HANDLERS.get(spec.name)
    if handler is not None:
        parser.set_defaults(handler=handler)
        return
    parser.set_defaults(handler=_not_implemented, command_name=spec.name, scan=spec.scan)


def build_parser() -> argparse.ArgumentParser:
    """Build the ``homenet`` argument parser."""
    parser = argparse.ArgumentParser(
        prog="homenet",
        description=(
            "Beginner-friendly tools for seeing what is on your home network.\n"
            "homenet wraps nmap so you can list devices, ports, and services\n"
            "without learning nmap's flags.\n"
            "\n"
            f"{BANNER}"
        ),
        formatter_class=_HelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", metavar="command")
    subparsers.required = True
    for spec in _COMMANDS:
        _add_command(subparsers, spec)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI. Returns a process exit code."""
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    return int(args.handler(args))

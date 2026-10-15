"""Beginner-friendly command line for home network detection.

``doctor`` asks :mod:`homenet.core.checks` for results and prints them.
This module does not spawn system commands itself.
"""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from dataclasses import dataclass

from homenet.core import checks
from homenet.core.checks import CheckResult

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


_COMMANDS: tuple[_Command, ...] = (
    _Command(
        "whoami-net",
        "Show this computer's address on your home network",
        "Show this computer's IP address, the interface it is using, "
        "and the home network it belongs to.",
        "homenet whoami-net",
        scan=True,
    ),
    _Command(
        "devices",
        "List devices currently on your home network",
        "Look for computers, phones, printers, and other devices on your "
        "home network and print a simple list.",
        "homenet devices",
        scan=True,
    ),
    _Command(
        "device",
        "Show details for one device by its IP address",
        "Show what we know about a single device. Use the IP address you "
        "saw from `homenet devices`.",
        "homenet device 192.168.1.20",
        scan=True,
        ip=True,
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
        "`homenet baseline`, and list anything new.",
        "homenet new-devices",
        scan=True,
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
        "Check that nmap and the ip command are installed, that you are allowed "
        "to scan, and that this computer has a network route. Run this first if a scan fails.",
        "homenet doctor",
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
        lines.append(f"{status}  {result.name:<{_NAME_WIDTH}} {result.detail}")
        if status != "PASS" and result.fix_hint:
            lines.append(f"      Fix: {result.fix_hint}")
    lines.append("")
    lines.append(_summary(results))
    return "\n".join(lines)


def _run_doctor(_args: argparse.Namespace) -> int:
    results = checks.run_all_checks()
    print(_format_doctor(results))
    return 1 if any(_is_error(result) for result in results) else 0


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
    if spec.name == "doctor":
        parser.set_defaults(handler=_run_doctor)
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

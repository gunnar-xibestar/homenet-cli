"""Beginner-friendly command line for home network detection.

``doctor`` asks :mod:`homenet.core.checks` for results and prints them.
``whoami-net`` asks :mod:`homenet.core.netinfo` and prints them.
``devices``, ``device``, ``baseline``, and ``new-devices`` ask
:mod:`homenet.core.devices` and :mod:`homenet.core.baseline`.
``ports`` asks :func:`homenet.core.ports.scan_ports` (top 100) and
:func:`homenet.core.port_notes.notes_for_ports`.
``services`` asks :func:`homenet.core.ports.scan_services` for one host.
It does not pass ``allow_subnet``.
``router`` asks :func:`homenet.core.router.check_router_admin`.
``speed`` asks :func:`homenet.core.speed.measure_download`. Unless ``--json``,
it passes ``on_progress`` and prints that callback on stderr.
``wifi`` asks :func:`homenet.core.wifi.get_wifi_info`.
``dns`` asks :func:`homenet.core.dns.get_dns_servers` and
:func:`homenet.core.dns.dns_lookup_test`. When
:func:`homenet.core.netinfo.detect` can see a gateway, a DNS server at that
address is labeled as the router.
The home network scans come from core. This module does not spawn commands
or read ``/sys``. ``devices`` labels this computer from the
:class:`~homenet.core.netinfo.NetInfo` core already collected, including ``mac``.

``new-devices`` exits 0 when the live scan matches the saved snapshot,
1 when a device is new, missing, changed, or has a different MAC address,
and 2 when the command fails.
``ports``, ``services``, ``router``, and ``speed`` exit 0 on success and 1
on failure. ``wifi`` and ``dns`` exit 0, including when Wi-Fi is unavailable,
inside WSL, or when the lookup does not succeed. Neither needs sudo.
Usage errors exit 2.
A closed stdout pipe, such as ``homenet devices | head``, exits 1 with no
traceback.
``--json`` prints the shapes documented in :mod:`homenet.output` to stdout,
with no banner. Errors go to stderr as a JSON object with ``error`` and
``fix_hint``.
Plain stdout gets padding lines of a single middle dot (U+00B7), or a
plain ``.`` when stdout's encoding is not UTF-8. The stdout wrapper writes
:data:`_LEADING_BLANK_LINES` of them immediately before the first write of a
non-JSON run, so a scan banner is not held until the scan ends. If that
first write is an error from :func:`_fail_message` (``args._failed`` is
already set), the error is written with no leading lines. A banner printed
before a later failure keeps the lines already shown. After the handler
returns, :data:`_TRAILING_BLANK_LINES` follow the output, but not for
``--json`` and not when :func:`_fail_message` ran. ``new-devices`` still
gets both when it finds changes and exits 1. ``--help``, ``--version``, and
usage errors leave argparse before the handler and stay unchanged. The five
trailing lines always follow newline-terminated output. Blank lines already
in that output are not the padding, so they do not reduce the five.
homenet never runs sudo or asks for a password. A ``sudo homenet ...``
prompt belongs to sudo and finishes before this process starts, so those
two lines are the first stdout after it.

On a terminal, a scan, sweep, HTTP check, Wi-Fi read, or DNS check shows a
status line on stderr (a spinner and the elapsed time) and clears it when the
step finishes.
``--json`` and a non-terminal stderr leave that line off, so stdout stays
intact. ``speed`` is the exception: progress is still on without ``--json``.
On a terminal it rewrites one stderr line with a carriage return, for example
``Testing download speed... 3s of 8s, about 212 Mbps so far``, and says
``warming up`` while megabits per second are 0. That line is cleared before
the result or an error is printed. When stderr is not a terminal, each update
is a plain line with no carriage return. ``--json`` does not pass
``on_progress`` and writes no progress on stdout. There is no flag to turn
progress off.
``-v`` prints core ``on_step`` text to stderr. ``-vv`` also passes
``stats_every=5`` and relays nmap progress. Displayed text goes through
:func:`homenet.output._clean`. ``baseline`` calls
:func:`homenet.core.baseline.take_baseline` and ``new-devices`` calls
:func:`homenet.core.baseline.check_new_devices`.

``--show-cmd`` installs :func:`homenet.core.commands.set_command_hook`. Before
each real command runs, the hook prints ``$ <display>`` to stderr. ``display``
and the purpose go through :func:`homenet.output._clean`. With ``--json`` the
hook does not print; the JSON object gains a top-level ``commands`` list instead.

``explain`` prints those commands and their purposes without running them.
``explain`` takes ``--network``. ``explain router`` also takes ``--gateway``.
The ``router`` command itself does not. Those options supply the home network
so explain does not run ``ip``. Without them, it calls
:func:`homenet.core.netinfo.detect`, which may run ``ip``. A bad ``--network``
or a planner ``ValueError`` for a bad target is shown as the usual
invalid-target error, with no traceback.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import sys
import threading
import time
from collections.abc import Callable, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as distribution_version
from typing import TextIO

from homenet import __version__
from homenet.core import (
    baseline,
    checks,
    devices,
    dns,
    netinfo,
    port_notes,
    ports,
    router,
    speed,
    wifi,
)
from homenet.core.baseline import BaselineError
from homenet.core.checks import CheckResult
from homenet.core.commands import planned_commands, set_command_hook
from homenet.core.parser import Device, ParseError
from homenet.core.runner import NmapError
from homenet.core.wsl import is_wsl
from homenet.output import (
    _clean,
    format_device,
    format_device_json,
    format_devices,
    format_devices_json,
    format_diff,
    format_diff_json,
    format_dns,
    format_dns_json,
    format_doctor_json,
    format_error,
    format_error_json,
    format_explain_json,
    format_ports,
    format_ports_json,
    format_router,
    format_router_json,
    format_services,
    format_services_json,
    format_speed,
    format_speed_json,
    format_whoami,
    format_whoami_json,
    format_wifi,
    format_wifi_json,
    merge_commands,
)

BANNER = "Only scan networks you own or have permission to scan."
_FRAMES = ("|", "/", "-", "\\")
_TICK = 0.1
_STATS_EVERY = 5
# Two padding lines before the first plain stdout write, and five after a run
# that did not fail. Each line is one middle dot (U+00B7), or "." when
# stdout's encoding is not UTF-8. A pure error (the first write is from
# _fail_message) and --json skip the leading lines. Trailing lines are
# skipped for --json and whenever _fail_message ran.
_LEADING_BLANK_LINES = 2
_TRAILING_BLANK_LINES = 5
_USAGE_HINT = "Run `homenet --help`, or `homenet <command> --help`, to see the options."
_VERBOSE_HELP = "Show each step on stderr. Repeat (-vv) to include nmap's progress."
_SHOW_CMD_HELP = "Show each real command on stderr as `$ command` before it runs."
_SHOW_CMD_JSON_HELP = f"{_SHOW_CMD_HELP} With --json, add a commands list instead of those lines."
_INVALID_TARGET_HINT = "Use an IP address or subnet like 192.168.1.0/24."
_SCAN_COMMANDS = frozenset({"devices", "device", "baseline", "new-devices"})
_HOST_COMMANDS = frozenset({"device", "ports", "services"})
_NETWORK_COMMANDS = frozenset({*_SCAN_COMMANDS, "ports", "services", "router"})


def _package_version() -> str:
    """Version from installed metadata, or the in-tree ``__version__`` fallback."""
    try:
        return distribution_version("homenet-cli")
    except PackageNotFoundError:
        return __version__


class _JsonAwareParser(argparse.ArgumentParser):
    """Usage errors stay plain text unless the user passed ``--json``."""

    def __init__(self, *args, json_mode: bool = False, **kwargs) -> None:
        self.json_mode = json_mode
        super().__init__(*args, **kwargs)

    def error(self, message: str) -> None:
        if self.json_mode:
            print(format_error_json(message, _USAGE_HINT), file=sys.stderr)
            self.exit(2)
        super().error(message)


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
    sudo: bool = False


# Root changes the ping sweep: nmap then reports MAC addresses and makers.
# ports (-sT), services (-sT -sV), and router (HTTP) do not.
_SUDO_SECTION = (
    "Running with sudo (Debian/Ubuntu)\n"
    "  Root adds MAC addresses and makers for devices, device, baseline,\n"
    "  and new-devices. sudo resets PATH, so plain `sudo homenet` cannot\n"
    '  find a venv\'s homenet and fails with "command not found". Look the\n'
    "  program up in your own shell first:\n"
    "\n"
    '    sudo "$(command -v homenet)" devices\n'
    "\n"
    "  The same form works for a pipx install. doctor, whoami-net, explain,\n"
    "  speed, wifi, and dns do not need sudo."
)


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
        sudo=True,
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
        sudo=True,
    ),
    _Command(
        "ports",
        "List open ports on one device",
        "List the open ports on one device and explain the risk in plain English. "
        "An open port is a door a program is listening on, such as a website or a printer.",
        "homenet ports 192.168.1.1",
        scan=True,
        ip=True,
        json=True,
    ),
    _Command(
        "services",
        "Show the services running on one device",
        "Name the services running on one device, such as a web server or "
        "file sharing, and show the program and version when they can be identified.",
        "homenet services 192.168.1.1",
        scan=True,
        ip=True,
        json=True,
    ),
    _Command(
        "router",
        "Find your home router",
        "Find the router that connects your home network to the internet "
        "and check whether its admin page answers.",
        "homenet router",
        scan=True,
        json=True,
    ),
    _Command(
        "baseline",
        "Save a snapshot of the devices on your network",
        "Save a snapshot of the devices on your network right now. "
        "Later, `homenet new-devices` compares against this snapshot.",
        "homenet baseline",
        scan=True,
        sudo=True,
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
        sudo=True,
    ),
    _Command(
        "speed",
        "Check how fast your internet connection is",
        "Estimate your download speed with 4 connections to Cloudflare "
        "(speed.cloudflare.com) over about 8 seconds. The number is an estimate, "
        "not a full speed test.",
        "homenet speed",
        json=True,
    ),
    _Command(
        "wifi",
        "Show the Wi-Fi signal, band, and channel",
        "Show the Wi-Fi network this computer is using and the signal in plain words, "
        "such as Good (-55 dBm). One line explains whether that channel is on "
        "2.4 GHz, which reaches farther, or 5 GHz, which is faster at a shorter range.\n"
        "\n"
        "Inside WSL this prints a short note and still exits 0. wifi does not need sudo.",
        "homenet wifi",
        json=True,
    ),
    _Command(
        "dns",
        "Show DNS servers and try a lookup",
        "List the DNS servers this computer is using, say who they likely belong to, "
        "and look up example.com. The gateway is your router. A loopback address "
        "is this computer's local resolver, and the servers behind it are listed too. "
        "Cloudflare, Google, and Quad9 are named, including their IPv6 networks. "
        "Another private or link-local address is a device on your network. "
        "Any other public address is likely your internet provider.\n"
        "\n"
        "dns does not need sudo.",
        "homenet dns",
        json=True,
    ),
    _Command(
        "doctor",
        "Check that tools and permissions are ready",
        "Check that nmap, the ip command, and ping are installed, that you are allowed "
        "to scan, and that this computer has a network route. Run this first if a scan fails.\n"
        "\n"
        "nmcli, iw, and resolvectl are optional Wi-Fi and DNS tools. A missing one is a "
        "warning, so doctor still exits 0. Doctor does not need sudo. A privileges warning "
        "tells you how to re-run a scan so sudo can still find homenet.",
        "homenet doctor",
        json=True,
    ),
)


def _description(spec: _Command) -> str:
    if spec.scan:
        return f"{spec.description}\n\n{BANNER}"
    return spec.description


def _epilog(spec: _Command) -> str:
    example = f"Example:\n  {spec.example}"
    if spec.sudo:
        return f"{example}\n\n{_SUDO_SECTION}"
    return example


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
    results = list(checks.run_all_checks())
    for name in checks.OPTIONAL_TOOLS:
        results.append(checks.check_optional_tool(name))
    if args.json:
        _print_ok(args, format_doctor_json(results))
    else:
        print(_format_doctor(results))
    return 1 if any(_is_error(result) for result in results) else 0


def _on_step(args: argparse.Namespace) -> Callable[[str], None] | None:
    """Core progress text for ``-v`` and ``-vv``. None when the user did not ask."""
    if int(getattr(args, "verbose", 0) or 0) <= 0:
        return None
    return lambda message: _emit_verbose(args, message)


def _gateway() -> str | None:
    """Gateway from core, or None when this computer has no default route."""
    try:
        return netinfo.detect().gateway
    except netinfo.NetInfoError:
        return None


def _run_wifi(args: argparse.Namespace) -> int:
    with _activity(args, "Reading Wi-Fi…"):
        info = wifi.get_wifi_info(on_step=_on_step(args))
    if args.json:
        _print_ok(args, format_wifi_json(info))
    else:
        print(format_wifi(info))
    return 0


def _run_dns(args: argparse.Namespace) -> int:
    step = _on_step(args)
    with _activity(args, "Checking DNS…"):
        gateway = _gateway()
        config = dns.get_dns_servers(on_step=step)
        lookup = dns.dns_lookup_test(on_step=step)
    if args.json:
        _print_ok(args, format_dns_json(config, lookup, gateway, wsl=is_wsl()))
    else:
        print(format_dns(config, lookup, gateway, wsl=is_wsl()))
    return 0


def _run_whoami(args: argparse.Namespace) -> int:
    try:
        info = netinfo.detect()
    except netinfo.NetInfoError as exc:
        return _fail(args, exc)
    if args.json:
        _print_ok(args, format_whoami_json(info))
    else:
        print(format_whoami(info))
    return 0


def _run_devices(args: argparse.Namespace) -> int:
    _begin_scan(args)
    found = _scan_home(args)
    if found is None:
        return 1
    local = getattr(args, "_netinfo", None)
    if args.json:
        _print_ok(args, format_devices_json(found, local=local))
    else:
        print(format_devices(found, local=local))
    return 0


def _parse_device_ip(args: argparse.Namespace) -> tuple[str | None, int | None]:
    """Return ``(address, None)`` or ``(None, exit code)`` after printing an error."""
    try:
        address = ipaddress.ip_address(args.ip.strip())
    except ValueError:
        return None, _fail_message(
            args,
            f"{args.ip} is not a valid IP address.",
            "Use an address from `homenet devices`, for example 192.168.1.20.",
        )
    if address.version != 4:
        return None, _fail_message(
            args,
            f"{args.ip} is not an IPv4 address.",
            "homenet looks up IPv4 addresses. Use one from `homenet devices`.",
        )
    return str(address), None


def _run_device(args: argparse.Namespace) -> int:
    _begin_scan(args)
    address, code = _parse_device_ip(args)
    if address is None:
        return code if code is not None else 1
    ok, found = _lookup_home(args, address)
    if not ok:
        return 1
    if found is None:
        return _fail_message(
            args,
            f"No device was found at {address}.",
            "Run `homenet devices` to see which addresses answered.",
        )
    if args.json:
        _print_ok(args, format_device_json(found))
    else:
        print(format_device(found))
    return 0


def _run_baseline(args: argparse.Namespace) -> int:
    _begin_scan(args)
    try:
        network = _home_network()
    except netinfo.NetInfoError as exc:
        return _fail(args, exc)
    try:
        with _activity(args, f"Scanning {network}…"):
            path, found = baseline.take_baseline(
                network,
                local_network=network,
                resolve_names=True,
                **_scan_feedback(args),
            )
    except (netinfo.NetInfoError, NmapError, ParseError, BaselineError) as exc:
        return _fail(args, exc)
    count = len(found)
    noun = "device" if count == 1 else "devices"
    print(f"Saved {count} {noun} to {path}.")
    print("Compare later with `homenet new-devices`.")
    return 0


def _run_new_devices(args: argparse.Namespace) -> int:
    """Exit 0 when nothing changed, 1 when something changed, and 2 on error."""
    _begin_scan(args)
    # A missing snapshot fails before any network lookup. The check loads it again.
    try:
        baseline.load_baseline()
    except BaselineError as exc:
        return _fail(args, exc, code=2)
    try:
        network = _home_network()
    except netinfo.NetInfoError as exc:
        return _fail(args, exc, code=2)
    try:
        with _activity(args, f"Scanning {network}…"):
            report = baseline.check_new_devices(
                network,
                local_network=network,
                resolve_names=True,
                **_scan_feedback(args),
            )
    except (netinfo.NetInfoError, NmapError, ParseError, BaselineError) as exc:
        return _fail(args, exc, code=2)
    if args.json:
        _print_ok(args, format_diff_json(report))
    else:
        print(format_diff(report))
    return 1 if report.has_changes else 0


def _run_ports(args: argparse.Namespace) -> int:
    _begin_scan(args)
    target, code = _one_ipv4(args)
    if target is None:
        return code if code is not None else 1
    try:
        with _activity(args, f"Scanning {target}…"):
            found = ports.scan_ports(target, top_ports=100, **_scan_feedback(args))
    except (NmapError, ParseError) as exc:
        return _fail(args, exc)
    device, code = _answered(args, found, target)
    if device is None:
        return code if code is not None else 1
    notes = port_notes.notes_for_ports(device.ports)
    if args.json:
        _print_ok(args, format_ports_json(device, notes))
    else:
        print(format_ports(device, notes))
    return 0


def _run_services(args: argparse.Namespace) -> int:
    """One host only. ``allow_subnet`` stays at its default of False."""
    _begin_scan(args)
    target, code = _one_ipv4(args)
    if target is None:
        return code if code is not None else 1
    try:
        with _activity(args, f"Detecting services on {target}…"):
            found = ports.scan_services(target, top_ports=100, **_scan_feedback(args))
    except (NmapError, ParseError) as exc:
        return _fail(args, exc)
    device, code = _answered(args, found, target)
    if device is None:
        return code if code is not None else 1
    if args.json:
        _print_ok(args, format_services_json(device))
    else:
        print(format_services(device))
    return 0


def _run_router(args: argparse.Namespace) -> int:
    _begin_scan(args)
    try:
        with _activity(args, "Checking the router…"):
            result = router.check_router_admin()
    except NmapError as exc:
        return _fail(args, exc)
    if args.json:
        _print_ok(args, format_router_json(result))
    else:
        print(format_router(result))
    return 0


def _clock_token(value: float) -> str:
    """``3s`` or ``8s`` when the value is a whole number of seconds."""
    number = float(value)
    if number.is_integer():
        return f"{int(number)}s"
    text = f"{number:.3f}".rstrip("0").rstrip(".")
    return f"{text}s"


def _speed_progress_line(elapsed_s: float, total_s: float, mbps: float) -> str:
    """One stderr status line. ``mbps`` 0.0 is warmup."""
    elapsed = _clock_token(elapsed_s)
    total = _clock_token(total_s)
    if mbps == 0.0:
        detail = "warming up"
    else:
        detail = f"about {round(mbps)} Mbps so far"
    text = f"Testing download speed... {elapsed} of {total}, {detail}"
    return _clean(text) or ""


class _SpeedProgress:
    """Live download line on stderr. Carriage return only when stderr is a TTY."""

    def __init__(self) -> None:
        self._stream = sys.stderr
        self._lock = threading.Lock()
        self._width = 0
        self._tty = _stderr_is_tty()

    def update(self, elapsed_s: float, total_s: float, mbps: float) -> None:
        text = _speed_progress_line(elapsed_s, total_s, mbps)
        if not text:
            return
        with self._lock:
            if self._tty:
                self._paint(text)
            else:
                self._stream.write(f"{text}\n")
                self._stream.flush()

    def _paint(self, text: str) -> None:
        pad = " " * max(0, self._width - len(text))
        self._stream.write(f"\r{text}{pad}")
        self._stream.flush()
        self._width = len(text)

    def write_line(self, text: str) -> None:
        """Clear the live line, then print ``text`` so the two do not share a row."""
        with self._lock:
            if self._tty and self._width:
                blank = " " * self._width
                self._stream.write(f"\r{blank}\r{text}\n")
                self._width = 0
            else:
                self._stream.write(f"{text}\n")
            self._stream.flush()

    def clear(self) -> None:
        """Erase the carriage-return line. Plain lines are already finished."""
        with self._lock:
            if self._width:
                self._stream.write("\r" + " " * self._width + "\r")
                self._stream.flush()
                self._width = 0


def _stderr_is_tty() -> bool:
    try:
        return bool(sys.stderr.isatty())
    except (AttributeError, OSError, ValueError):
        return False


def _run_speed(args: argparse.Namespace) -> int:
    """Run the download. Clear the live line before the result or any error."""
    progress = None if getattr(args, "json", False) else _SpeedProgress()
    args._status = progress
    failure: speed.SpeedError | None = None
    result = None
    try:
        if progress is None:
            result = speed.measure_download()
        else:
            result = speed.measure_download(on_progress=progress.update)
    except speed.SpeedError as exc:
        failure = exc
    finally:
        if progress is not None:
            progress.clear()
        args._status = None
    if failure is not None:
        return _fail(args, failure)
    if args.json:
        _print_ok(args, format_speed_json(result))
    else:
        print(format_speed(result))
    return 0


def _one_ipv4(args: argparse.Namespace) -> tuple[str | None, int | None]:
    """Return ``(address, None)`` or ``(None, exit code)`` after printing an error."""
    raw = str(args.ip).strip()
    if not raw or "/" in raw:
        message = (
            f"{raw} is a subnet, and {args.command} checks one device."
            if "/" in raw
            else "That is not a valid IP address."
        )
        return None, _fail_message(
            args,
            message,
            "Use one IP address, for example 192.168.1.20.",
        )
    try:
        address = ipaddress.ip_address(raw)
    except ValueError:
        return None, _fail_message(
            args,
            f"{raw} is not a valid IP address.",
            "Use an address from `homenet devices`, for example 192.168.1.20.",
        )
    if address.version != 4:
        return None, _fail_message(
            args,
            f"{address} is not an IPv4 address.",
            "homenet checks IPv4 addresses. Use one from `homenet devices`.",
        )
    return str(address), None


def _answered(
    args: argparse.Namespace, found: list[Device], target: str
) -> tuple[Device | None, int | None]:
    device = _match_host(found, target)
    if device is None:
        return None, _fail_message(
            args,
            f"No device answered at {target}.",
            "Check the address with `homenet devices`, and that the device is turned on.",
        )
    return device, None


def _match_host(found: Sequence[Device], target: str) -> Device | None:
    want = ipaddress.ip_address(target)
    for device in found:
        try:
            if ipaddress.ip_address(device.ip) == want:
                return device
        except ValueError:
            continue
    return None


class _StatusLine:
    """Spinner and elapsed time on stderr. One daemon thread, drawn with ``\\r``."""

    def __init__(self, label: str) -> None:
        self._label = label
        self._stream = sys.stderr
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._width = 0
        self._started = time.monotonic()
        self._thread = threading.Thread(target=self._run, name="homenet-status", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def _run(self) -> None:
        index = 0
        while not self._stop.is_set():
            elapsed = int(time.monotonic() - self._started)
            frame = _FRAMES[index % len(_FRAMES)]
            index += 1
            text = f"{frame} {self._label} ({elapsed}s)"
            with self._lock:
                if self._stop.is_set():
                    return
                self._paint(text)
            if self._stop.wait(_TICK):
                return

    def _paint(self, text: str) -> None:
        pad = " " * max(0, self._width - len(text))
        self._stream.write(f"\r{text}{pad}")
        self._stream.flush()
        self._width = len(text)

    def write_line(self, text: str) -> None:
        """Clear the status line, then print ``text`` so the two do not share a row."""
        with self._lock:
            blank = " " * self._width
            self._stream.write(f"\r{blank}\r{text}\n")
            self._stream.flush()
            self._width = 0

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=1)
        with self._lock:
            if self._width:
                self._stream.write("\r" + " " * self._width + "\r")
                self._stream.flush()
                self._width = 0


def _spinner_enabled(args: argparse.Namespace) -> bool:
    """Progress is on by default, except for ``--json`` and a non-terminal stderr."""
    if getattr(args, "json", False):
        return False
    return _stderr_is_tty()


def _verbose_count(argv: Sequence[str]) -> int:
    """How many ``-v`` / ``--verbose`` flags were given, including ``-vv``."""
    count = 0
    for arg in argv:
        if arg == "--":
            break
        if arg == "--verbose":
            count += 1
        elif (
            len(arg) > 1
            and arg.startswith("-")
            and not arg.startswith("--")
            and set(arg[1:]) == {"v"}
        ):
            count += len(arg) - 1
    return count


def _write_err(args: argparse.Namespace, text: str) -> None:
    """Print one stderr line, clearing the status line first when it is up."""
    status = getattr(args, "_status", None)
    if status is not None:
        status.write_line(text)
    else:
        print(text, file=sys.stderr)


def _emit_verbose(args: argparse.Namespace, message: str) -> None:
    text = _clean(message)
    if text:
        _write_err(args, text)


def _scan_feedback(args: argparse.Namespace) -> dict:
    """``on_step`` at ``-v``. ``stats_every`` and ``on_progress`` at ``-vv``."""
    level = int(getattr(args, "verbose", 0) or 0)
    if level <= 0:
        return {}
    feedback: dict = {"on_step": lambda message: _emit_verbose(args, message)}
    if level >= 2:
        feedback["stats_every"] = _STATS_EVERY
        feedback["on_progress"] = lambda message: _emit_verbose(args, message)
    return feedback


@contextmanager
def _activity(args: argparse.Namespace, label: str):
    """Show ``label`` on stderr while ``yield`` runs, when the spinner is enabled."""
    status = _StatusLine(_clean(label) or "Working…") if _spinner_enabled(args) else None
    args._status = status
    try:
        if status is not None:
            try:
                sys.stdout.flush()
            except OSError:
                pass
            status.start()
        yield
    finally:
        args._status = None
        if status is not None:
            status.stop()


def _begin_scan(args: argparse.Namespace) -> None:
    """Remind the user to scan only networks they own. JSON stays banner-free."""
    if getattr(args, "json", False):
        return
    print(BANNER)
    print()


def _subnet_from(info: netinfo.NetInfo) -> str:
    """IPv4 subnet from ``info``, or raise :class:`NetInfoError` with a fix hint."""
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


def _home_network() -> str:
    """IPv4 subnet from netinfo, or raise :class:`NetInfoError` with a fix hint."""
    return _subnet_from(netinfo.detect())


def _scan_home(args: argparse.Namespace) -> list[Device] | None:
    """Sweep the netinfo subnet. None means the error was already printed."""
    try:
        info = netinfo.detect()
        network = _subnet_from(info)
    except netinfo.NetInfoError as exc:
        _fail(args, exc)
        return None
    args._netinfo = info
    try:
        with _activity(args, f"Scanning {network}…"):
            return devices.sweep(
                network,
                local_network=network,
                resolve_names=True,
                **_scan_feedback(args),
            )
    except (NmapError, ParseError) as exc:
        _fail(args, exc)
        return None


def _lookup_home(args: argparse.Namespace, ip: str) -> tuple[bool, Device | None]:
    """Return ``(True, device)``. The device is None when that address did not answer.

    ``(False, None)`` means an error was already printed.
    """
    try:
        network = _home_network()
    except netinfo.NetInfoError as exc:
        _fail(args, exc)
        return False, None
    try:
        with _activity(args, f"Scanning {network}…"):
            return True, devices.get_device(
                network,
                ip=ip,
                local_network=network,
                resolve_names=True,
                **_scan_feedback(args),
            )
    except (NmapError, ParseError) as exc:
        _fail(args, exc)
        return False, None


def _fail(args: argparse.Namespace, exc: BaseException, code: int = 1) -> int:
    hint = getattr(exc, "hint", None)
    return _fail_message(args, str(exc), hint if isinstance(hint, str) else None, code)


def _fail_message(args: argparse.Namespace, message: str, hint: str | None, code: int = 1) -> int:
    """Beginner-friendly error. ``--json`` writes ``{"error", "fix_hint"}`` to stderr.

    ``code`` is 2 for ``new-devices`` failures and 1 for every other command.
    ``--show-cmd --json`` also includes the ``commands`` seen before the failure.
    Sets ``args._failed`` before printing, so a pure error (this is the first
    stdout write) gets no leading padding, and :func:`main` adds no trailing
    lines either. A banner already printed stays as it was.
    """
    args._failed = True
    if getattr(args, "json", False):
        text = format_error_json(message, hint)
        if getattr(args, "show_cmd", False):
            text = merge_commands(text, _command_payloads(getattr(args, "_shown_commands", [])))
        print(text, file=sys.stderr)
    else:
        print(format_error(message, hint))
    return code


def _command_payloads(commands: Sequence[object]) -> list[dict]:
    """``Command.to_dict()`` with displayed strings cleaned.

    ``argv`` stays the real argument list. ``display`` and ``purpose`` go
    through :func:`_clean` so a hostname or address cannot change the terminal.
    """
    payloads: list[dict] = []
    for cmd in commands:
        data = cmd.to_dict()
        data["display"] = _clean(data.get("display")) or ""
        data["purpose"] = _clean(data.get("purpose")) or ""
        payloads.append(data)
    return payloads


def _print_ok(args: argparse.Namespace, text: str) -> None:
    """Print a successful JSON document, adding ``commands`` when asked."""
    if getattr(args, "show_cmd", False):
        text = merge_commands(text, _command_payloads(getattr(args, "_shown_commands", [])))
    print(text)


def _capture_commands(args: argparse.Namespace) -> None:
    """Remember every real command. Print ``$`` lines unless ``--json`` is set.

    ``explain`` prints the planned commands itself, so it does not install the hook.
    Detection inside explain can run ``ip``; that lookup is not listed twice.
    """
    captured: list = []
    args._shown_commands = captured
    if not getattr(args, "show_cmd", False) or args.command == "explain":
        set_command_hook(None)
        return

    def hook(cmd: object) -> None:
        captured.append(cmd)
        if getattr(args, "json", False):
            return
        shown = _clean(cmd.display())
        if shown:
            _write_err(args, f"$ {shown}")

    set_command_hook(hook)


def _failure_code(name: str) -> int:
    """Exit status the real command uses when it fails."""
    return 2 if name == "new-devices" else 1


def _invalid_target(target: str | None) -> tuple[str, str]:
    """Same wording as a scan that rejects a target that is not an IP or subnet."""
    if target:
        message = f"{target!r} is not a valid IP address or subnet."
    else:
        message = "That is not a valid IP address or subnet."
    return message, _INVALID_TARGET_HINT


def _format_explained(commands: Sequence[object]) -> str:
    blocks: list[str] = []
    for item in _command_payloads(commands):
        display = item["display"]
        purpose = item["purpose"]
        blocks.append(f"$ {display}\n  {purpose}" if purpose else f"$ {display}")
    return "\n\n".join(blocks)


def _explain_host(args: argparse.Namespace, name: str) -> tuple[str | None, int | None]:
    """Validate an explain target with the same messages as the real command."""
    target = args.target
    if not target:
        return None, _fail_message(
            args,
            f"{name} needs an IP address.",
            f"For example: homenet explain {name} 192.168.1.20",
            code=2,
        )
    saved = args.command
    args.command = name
    args.ip = target
    try:
        if name == "device":
            return _parse_device_ip(args)
        return _one_ipv4(args)
    finally:
        args.command = saved


def _supplied_network(args: argparse.Namespace, code: int) -> tuple[str | None, int | None]:
    """Return ``(cidr, None)`` or ``(None, exit code)`` after a friendly error.

    ``(None, None)`` means ``--network`` was not passed. A bad CIDR uses the
    same invalid-target message as a scan that rejects the address.
    """
    raw = getattr(args, "network", None)
    if raw is None:
        return None, None
    text = str(raw).strip()
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError:
        message, hint = _invalid_target(text or str(raw))
        return None, _fail_message(args, message, hint, code)
    if network.version != 4:
        message, hint = _invalid_target(text)
        return None, _fail_message(args, message, hint, code)
    return str(network), None


def _supplied_gateway(args: argparse.Namespace, code: int) -> tuple[str | None, int | None]:
    """Return ``(ip, None)``, ``(None, None)`` if omitted, or ``(None, exit code)``."""
    raw = getattr(args, "gateway", None)
    if raw is None:
        return None, None
    text = str(raw).strip()
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        message, hint = _invalid_target(text or str(raw))
        return None, _fail_message(args, message, hint, code)
    if address.version != 4:
        message, hint = _invalid_target(text)
        return None, _fail_message(args, message, hint, code)
    return str(address), None


def _explain_params(name: str, ip: str | None, network: str | None, gateway: str | None) -> dict:
    if name in _SCAN_COMMANDS:
        return {"local_network": network}
    if name == "ports":
        return {"target": ip, "local_network": network, "top_ports": 100}
    if name == "services":
        return {
            "target": ip,
            "local_network": network,
            "top_ports": 100,
            "allow_subnet": False,
        }
    if name == "router":
        return {"gateway": gateway, "local_network": network}
    return {}


def _run_explain(args: argparse.Namespace) -> int:
    """Print the real commands for one homenet command. Does not scan."""
    name = args.subject
    code = _failure_code(name)
    ip: str | None = None
    if name in _HOST_COMMANDS:
        ip, err = _explain_host(args, name)
        if ip is None:
            return err if err is not None else code
    elif args.target:
        return _fail_message(
            args,
            f"{name} does not take an IP address.",
            f"Try `homenet explain {name}`.",
            code=2,
        )

    supplied, err = _supplied_network(args, code)
    if err is not None:
        return err
    supplied_gw, err = _supplied_gateway(args, code)
    if err is not None:
        return err

    network: str | None = None
    gateway: str | None = None
    if name in _NETWORK_COMMANDS:
        if supplied is not None:
            network = supplied
            gateway = supplied_gw
        else:
            try:
                info = netinfo.detect()
                network = _subnet_from(info)
            except netinfo.NetInfoError as exc:
                return _fail(args, exc, code)
            detected = (info.gateway or "").strip() or None
            gateway = supplied_gw if supplied_gw is not None else detected

    try:
        planned = planned_commands(name, **_explain_params(name, ip, network, gateway))
    except ValueError:
        message, hint = _invalid_target(ip if name in _HOST_COMMANDS else None)
        return _fail_message(args, message, hint, code)
    except (NmapError, netinfo.NetInfoError, speed.SpeedError) as exc:
        return _fail(args, exc, code)

    if args.json:
        print(format_explain_json(name, _command_payloads(planned)))
    else:
        print(_format_explained(planned))
    return 0


_HANDLERS = {
    "doctor": _run_doctor,
    "whoami-net": _run_whoami,
    "devices": _run_devices,
    "device": _run_device,
    "ports": _run_ports,
    "services": _run_services,
    "router": _run_router,
    "baseline": _run_baseline,
    "new-devices": _run_new_devices,
    "speed": _run_speed,
    "wifi": _run_wifi,
    "dns": _run_dns,
}


def _add_command(subparsers, spec: _Command, json_mode: bool) -> None:
    parser = subparsers.add_parser(
        spec.name,
        help=spec.summary,
        description=_description(spec),
        epilog=_epilog(spec),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.json_mode = json_mode
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
    _add_verbose(parser)
    _add_show_cmd(parser, json=spec.json)
    handler = _HANDLERS.get(spec.name)
    if handler is not None:
        parser.set_defaults(handler=handler)
        return
    parser.set_defaults(handler=_not_implemented, command_name=spec.name, scan=spec.scan)


def build_parser(json_mode: bool = False) -> argparse.ArgumentParser:
    """Build the ``homenet`` argument parser."""
    parser = _JsonAwareParser(
        prog="homenet",
        description=(
            "Beginner-friendly tools for seeing what is on your home network.\n"
            "homenet wraps nmap so you can list devices, ports, and services\n"
            "without learning nmap's flags.\n"
            "\n"
            f"{BANNER}"
        ),
        epilog=_SUDO_SECTION,
        formatter_class=_HelpFormatter,
        json_mode=json_mode,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {_package_version()}",
    )
    _add_verbose(parser)
    _add_show_cmd(parser, json=True)
    subparsers = parser.add_subparsers(dest="command", metavar="command")
    subparsers.required = True
    for spec in _COMMANDS:
        _add_command(subparsers, spec, json_mode)
    _add_explain(subparsers, json_mode)
    return parser


def _add_verbose(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("-v", "--verbose", action="count", default=0, help=_VERBOSE_HELP)


def _add_show_cmd(parser: argparse.ArgumentParser, *, json: bool = False) -> None:
    parser.add_argument(
        "--show-cmd",
        action="store_true",
        help=_SHOW_CMD_JSON_HELP if json else _SHOW_CMD_HELP,
    )


def _add_explain(subparsers, json_mode: bool) -> None:
    names = ", ".join(spec.name for spec in _COMMANDS)
    parser = subparsers.add_parser(
        "explain",
        help="Show the real commands a command would run, without running them",
        description=(
            "Print each real command homenet would run, and why, without running it.\n"
            "Pass --network to give the home network. --gateway is only for\n"
            "`explain router`. The router command does not take --gateway.\n"
            "Those options skip the ip lookup. Without them, explain looks the network\n"
            "up the same way a real run does, which may run the `ip` command. It is not\n"
            "a scan. If the lookup fails, homenet prints the usual error and fix hint.\n"
            "\n"
            f"command is one of: {names}."
        ),
        epilog="Example:\n  homenet explain devices\n  homenet explain ports 192.168.1.1",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.json_mode = json_mode
    parser.add_argument(
        "subject",
        metavar="command",
        choices=[spec.name for spec in _COMMANDS],
        help=f"Command to explain. One of: {names}",
    )
    parser.add_argument(
        "target",
        nargs="?",
        metavar="IP",
        help="IP address, when that command needs one. For example 192.168.1.20",
    )
    parser.add_argument(
        "--network",
        metavar="CIDR",
        help="Home network to assume, for example 192.168.1.0/24. Skips the ip lookup.",
    )
    parser.add_argument(
        "--gateway",
        metavar="IP",
        help=(
            "Router address for explain router, for example 192.168.1.1. "
            "The router command does not take this."
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print JSON to stdout, with no banner. Errors go to stderr as JSON.",
    )
    _add_verbose(parser)
    _add_show_cmd(parser, json=True)
    parser.set_defaults(handler=_run_explain)


def _padding_mark(stream: TextIO) -> str:
    """One character for a padding line.

    UTF-8 stdout gets U+00B7 MIDDLE DOT. Any other encoding, including a
    missing one, gets ASCII ``.``.
    """
    encoding = getattr(stream, "encoding", None)
    if isinstance(encoding, str) and encoding.lower().replace("_", "-") in {"utf-8", "utf8"}:
        return "\u00b7"
    return "."


def _padding_lines(stream: TextIO, count: int) -> str:
    """``count`` padding lines. Each line is one mark from :func:`_padding_mark`."""
    return f"{_padding_mark(stream)}\n" * count


class _StdoutTail:
    """Forward stdout and remember whether it already ends with a newline.

    ``main`` installs this around one command handler. Bytes are written
    through immediately. The first non-empty write of a non-JSON run is
    preceded by :data:`_LEADING_BLANK_LINES` padding lines, unless
    ``args._failed`` is already set (the first print is an error from
    :func:`_fail_message`). Afterwards, :meth:`padding` is
    :data:`_TRAILING_BLANK_LINES` lines, each a single padding mark. Those
    lines are always written once the output ends with a newline. Blank lines
    the handler already printed are not padding, so they do not reduce the five.
    """

    def __init__(self, stream: TextIO, args: argparse.Namespace) -> None:
        self._stream = stream
        self._args = args
        self._opened = False
        self._ends_with_newline = False
        self._had_content = False

    def write(self, text: str) -> int:
        """Write ``text`` now. Leading lines go out before the first real write."""
        if text and not self._opened:
            self._opened = True
            # _fail_message sets _failed before it prints, so a pure error
            # is not padded. A banner printed earlier already took this branch.
            if not getattr(self._args, "json", False) and not getattr(self._args, "_failed", False):
                self._stream.write(_padding_lines(self._stream, _LEADING_BLANK_LINES))
        written = self._stream.write(text)
        if text:
            self._had_content = True
            self._ends_with_newline = text.endswith("\n")
        return written

    def padding(self) -> str:
        """Five padding lines, after a newline when the last line is unfinished.

        Each line is one middle dot, or ``.`` when stdout is not UTF-8.
        ``print`` already ends its text with a newline, so the usual case is
        just those five lines. Output that already ends with blank lines is
        still newline-terminated: the five lines follow the blanks. A blank
        line is not a padding line, so an existing run does not shorten them.
        """
        lines = _padding_lines(self._stream, _TRAILING_BLANK_LINES)
        if self._had_content and not self._ends_with_newline:
            return "\n" + lines
        return lines

    def __getattr__(self, name: str) -> object:
        return getattr(self._stream, name)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI. Returns a process exit code.

    The stdout wrapper writes :data:`_LEADING_BLANK_LINES` padding lines
    immediately before the first write of a non-JSON run, unless that write
    is an error from :func:`_fail_message`. After the handler returns, plain
    text is followed by :data:`_TRAILING_BLANK_LINES` padding lines. Each
    line is one middle dot, or ``.`` when stdout's encoding is not UTF-8.
    The trailing lines are always written once the output ends with a
    newline; blank lines already there do not replace them. ``--json`` skips
    them, and so does a run that printed an error through
    :func:`_fail_message`. The exit code does not matter: ``new-devices``
    exits 1 when it finds changes and still gets the gap. ``--help``,
    ``--version``, and usage errors exit inside ``parse_args`` and never
    reach this step. Output is not buffered: a scan banner is visible before
    the scan runs.

    ``BrokenPipeError`` (a reader such as ``head`` closed the pipe) exits 1
    with no traceback. Stdout is pointed at ``os.devnull`` first so the
    flush the interpreter runs at shutdown does not raise it again.
    """
    raw = list(argv) if argv is not None else list(sys.argv[1:])
    json_mode = "--json" in raw
    parser = build_parser(json_mode=json_mode)
    args = parser.parse_args(raw)
    # A flag before the command is stored on the top-level parser, then the
    # subparser default (False) replaces it. Honour whichever place it appeared.
    args.show_cmd = bool(getattr(args, "show_cmd", False) or "--show-cmd" in raw)
    # A ``-v`` before the command and another after it are both real. Count the raw argv.
    args.verbose = _verbose_count(raw)
    stdout = sys.stdout
    tail = _StdoutTail(stdout, args)
    sys.stdout = tail
    try:
        _capture_commands(args)
        code = int(args.handler(args))
        # Trailing padding before the next shell prompt. Leading lines already
        # went out, live, before the first write. JSON stays untouched, and so
        # does stdout after _fail_message.
        if not getattr(args, "_failed", False) and not getattr(args, "json", False):
            extra = tail.padding()
            if extra:
                stdout.write(extra)
        # A closed pipe must raise here, not while Python flushes at shutdown.
        stdout.flush()
        return code
    except BrokenPipeError:
        # Python flushes standard streams on exit; redirect remaining output
        # to devnull to avoid another BrokenPipeError at shutdown.
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        sys.exit(1)
    finally:
        sys.stdout = stdout
        set_command_hook(None)

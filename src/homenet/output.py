"""Plain-text and JSON views for the homenet CLI.

These functions only turn core data into text. They do not scan, print, or exit,
and they do not spawn system commands.

Input shapes for Net Core to match:

* :func:`format_whoami` takes one :class:`homenet.core.netinfo.NetInfo`.
  Fields it reads: ``interface``, ``ip``, ``gateway``, ``subnet``, ``wsl_nat``.
  The IP line is the address alone. A Network size line describes ``subnet``.
  This view does not show ``mac``.
  When ``wsl_nat`` is true, the plain view adds a warning that this may be the
  WSL virtual network, not the home LAN.
* :func:`format_devices` takes a sequence of :class:`homenet.core.parser.Device`
  (the host list for ``homenet devices``) and an optional ``local``
  :class:`~homenet.core.netinfo.NetInfo`. A row whose IP is ``local.ip`` is
  named ``this computer``. When that row has no MAC, the table and the JSON
  ``mac`` field use ``local.mac``. JSON ``mac`` stays null when ``local.mac`` is missing.
* :func:`format_device` takes one :class:`homenet.core.parser.Device`
  (the detail view for ``homenet device <ip>``), including its ``ports``
  list of :class:`homenet.core.parser.Port` (``number``, ``protocol``,
  ``state``, ``service``).
* :func:`format_diff` takes one :class:`homenet.core.baseline.DeviceDiff`
  (``new``, ``missing``, ``changed``, ``mac_changed``, ``has_changes``).
* :func:`format_ports` takes one :class:`~homenet.core.parser.Device` and the
  :class:`~homenet.core.port_notes.PortNote` list from ``notes_for_ports``.
* :func:`format_services` takes one device and shows ``product`` and ``version``.
* :func:`format_router` takes one :class:`~homenet.core.router.RouterCheck`.
* :func:`format_speed` takes one :class:`~homenet.core.speed.SpeedResult`.
  The plain view labels megabits per second as an estimate, then one line
  for how many connections ran and for about how long. When ``errors`` is
  not empty, a last line counts the connections that reported an error.
  ``wsl`` is not shown.
* :func:`format_wifi` takes one :class:`~homenet.core.wifi.WifiInfo`.
  The signal line is words plus a number, such as ``Good (-55 dBm)``.
  Thresholds are Excellent at -50 dBm or stronger, Good at -60, Fair at -70,
  and Weak below that. A missing dBm reading uses ``signal_percent``.
  If both are missing, the line says to install ``iw``.
  On WSL the plain view is the note that Wi-Fi info isn't visible inside WSL.
* :func:`format_dns` takes a :class:`~homenet.core.dns.DnsConfig`, a
  :class:`~homenet.core.dns.LookupResult`, and an optional gateway address.
  Each server is labeled, in order: the gateway is ``your router``; a loopback
  address is this computer's local resolver (upstream servers are listed too);
  Cloudflare, Google, and Quad9 ranges (IPv4 hosts and their IPv6 networks);
  any other private or link-local address is a device on your network; any
  other global address is likely the internet provider. The lookup is one line.

Missing device fields (``hostname``, ``mac``, ``vendor``, ``service``) are
shown as ``unknown``. Missing network fields are shown as ``not available``.

``--json`` shapes (keys sorted, ``null`` for a missing value). Every string
below has been passed through :func:`_clean`. :func:`json.dumps` escapes the
result (quotes, backslashes, and non-ASCII).

``homenet devices --json``::

    {"devices": [<device>, ...]}

``homenet device <ip> --json``::

    <device>

``homenet new-devices --json``::

    {"changed": [{"after": <device>, "before": <device>}, ...],
     "has_changes": bool,
     "mac_changed": [{"after": <device>, "before": <device>}, ...],
     "missing": [<device>, ...],
     "new": [<device>, ...]}

``homenet whoami-net --json``::

    {"address_count": int|null, "gateway": str|null, "interface": str|null,
     "ip": str|null, "prefix": int|null, "range_end": str|null,
     "range_start": str|null, "subnet": str|null, "warning": str|null,
     "wsl_nat": bool}

``ip`` is the address, without a prefix. ``prefix`` stays the subnet length
when the subnet parses and uses the same IP version as ``ip``, and is null
otherwise. ``address_count``, ``range_start``, and ``range_end`` match the
Network size line: how many addresses the subnet holds, and the first and
last. They are null when the subnet cannot be parsed. Existing keys stay.
``wsl_nat`` is true when the active address is inside WSL 2's NAT range.
``warning`` then says this may be the WSL virtual network, not the home LAN,
and how to switch WSL to mirrored networking. Otherwise ``warning`` is null.

``homenet doctor --json``::

    {"checks": [{"detail": str|null, "fix_hint": str|null, "name": str,
                 "ok": bool, "severity": "ok"|"warning"|"error"}, ...],
     "ok": bool}

On WSL 2 NAT, ``checks`` also includes a warning named ``wsl``. That warning
does not set ``ok`` to false.

``<device>``::

    {"hostname": str|null, "ip": str|null, "mac": str|null,
     "ports": [{"number": int, "protocol": str|null, "service": str|null,
                "state": str|null}, ...],
     "vendor": str|null}

``homenet devices --json`` adds ``"is_self": true`` on the device whose IP
is this computer. Other devices omit that key. When that device has no MAC,
``mac`` is filled from this computer's netinfo address, and stays null when
that address is unknown. Every other field stays as the scan reported it.

``homenet ports <ip> --json`` (open ports only)::

    {"hostname": str|null, "ip": str|null,
     "ports": [{"name": str|null, "note": str|null, "number": int,
                "protocol": str|null, "risk": str|null, "service": str|null,
                "state": str|null}, ...]}

``homenet services <ip> --json`` (open ports only)::

    {"hostname": str|null, "ip": str|null,
     "services": [{"number": int, "product": str|null, "protocol": str|null,
                   "service": str|null, "state": str|null,
                   "version": str|null}, ...]}

``homenet router --json``::

    {"admin_reachable": bool, "gateway": str|null,
     "pages": [{"error": str|null, "plain_http": bool, "port": int,
                "reachable": bool, "server": str|null, "status": int|null,
                "title": str|null, "url": str|null}, ...],
     "plain_http_reachable": bool}

``homenet speed --json``::

    {"bytes": int, "connections": int, "download_mbps": number,
     "errors": [str, ...], "median_mbps": number|null, "seconds": number,
     "total_bytes": int, "url": str|null, "warmup_s": number}

``download_mbps``, ``bytes``, ``seconds``, and ``url`` stay. The other keys
are added. ``errors`` lists each cleaned message (an empty string when a
message had no printable text). ``wsl`` is not a key.

``homenet wifi --json``::

    {"available": bool, "band": str|null, "band_note": str|null,
     "channel": int|null, "frequency_mhz": int|null, "interface": str|null,
     "link_speed_mbps": number|null, "message": str|null, "reason": str|null,
     "signal": str|null, "signal_dbm": int|null, "signal_percent": int|null,
     "ssid": str|null, "wsl": bool}

``signal`` is words plus a number when Wi-Fi is available, the same text as
the plain Signal row. ``message`` is the friendly reason when it is not,
including the WSL note. ``wifi`` exits 0 either way.

``homenet dns --json``::

    {"gateway": str|null,
     "lookup": {"addresses": [str, ...], "elapsed_ms": number|null,
                "error": str|null, "name": str|null, "ok": bool,
                "summary": str},
     "servers": [{"interface": str|null, "ip": str|null, "label": str,
                  "source": str|null}, ...],
     "source": str|null,
     "upstream": [{"ip": str, "label": str}, ...],
     "uses_systemd_stub": bool}

``label`` is who that server likely belongs to. ``summary`` is the one-line
lookup result. ``upstream`` is filled when a server is a local resolver.
``dns`` exits 0.

``homenet uninstall --json``::

    {"cancelled": bool, "data_kept": bool, "data_paths": [str, ...],
     "distribution": str, "install": "venv"|"pipx"|"user", "purged": bool,
     "removed_paths": [str, ...], "uninstalled": bool}

``install`` is how this copy was installed. ``data_paths`` is the baseline
file and its folder. ``removed_paths`` is filled only after ``--purge``
deletes them. ``data_kept`` is true when the uninstall finished, or was
cancelled, without deleting that data. Strings go through :func:`_clean`.
A system, editable, or unknown install is an error object, not this shape.
``--show-cmd --json`` adds ``commands`` the same way as other commands.

``doctor`` ``ok`` is false only when a check failed at error severity.
Warnings leave it true, including a missing ``nmcli``, ``iw``, or ``resolvectl``.
``new-devices`` exits 0 when ``has_changes`` is false,
1 when it is true, and 2 when the command fails.
``ports``, ``services``, ``router``, ``speed``, and ``uninstall`` exit 0 on
success and 1 when the command fails. ``uninstall`` also exits 0 when the
answer is no. No open ports, and a router with no admin page, are still
success. Argparse usage errors exit 2.

``--json`` errors are a JSON object on stderr::

    {"error": str, "fix_hint": str|null}

``--show-cmd --json`` adds a top-level ``commands`` list to that object and to
every successful JSON object. ``homenet explain --json`` is::

    {"command": str,
     "commands": [{"argv": [str, ...], "display": str, "purpose": str,
                   "kind": "exec"|"http"}, ...]}

``display`` and ``purpose`` have been passed through :func:`_clean`. ``argv``
is the argument list the command would actually use.
"""

from __future__ import annotations

import ipaddress
import json
from collections.abc import Sequence

from homenet.core._text import clean_text
from homenet.core.baseline import DeviceDiff
from homenet.core.checks import CheckResult
from homenet.core.devices import normalize_mac
from homenet.core.dns import DnsConfig, LookupResult
from homenet.core.netinfo import NetInfo
from homenet.core.parser import Device, Port
from homenet.core.port_notes import GENERIC_NOTE, PortNote
from homenet.core.router import AdminPage, RouterCheck
from homenet.core.speed import SpeedResult
from homenet.core.wifi import WifiInfo, percent_to_dbm
from homenet.core.wsl import WSL_NAT_FIX, wsl_nat_detail

_UNKNOWN = "unknown"
_NOT_AVAILABLE = "not available"
_INSTALL_LABELS = {
    "venv": "pip in a virtual environment",
    "user": "pip in your user site-packages",
    "pipx": "pipx",
}

_WHOAMI_NOTES = (
    "The interface is how this computer is connected, such as Wi-Fi.",
    "The IP address is this computer.",
    "The gateway is usually your home router.",
    "The home network is the group of addresses your devices share.",
)


def format_error(message: str, hint: str | None = None) -> str:
    """What went wrong, plus a fix when one is known.

    Both strings are cleaned. A hint can repeat an interface name from the network.
    """
    text, fix = _error_parts(message, hint)
    if fix:
        return f"{text}\nFix: {fix}"
    return text


def format_error_json(message: str, hint: str | None = None) -> str:
    """JSON error object for ``--json`` (written to stderr by the CLI).

    Shape: ``{"error": str, "fix_hint": str|null}``. Strings go through
    :func:`_clean`, then :func:`json.dumps`.
    """
    text, fix = _error_parts(message, hint)
    return _dumps({"error": text, "fix_hint": fix})


def format_uninstall_preview(
    distribution: str,
    kind: str,
    display: str,
    paths: Sequence[str],
    *,
    purge: bool,
) -> str:
    """Text shown before uninstall runs: the command, then the saved-data paths."""
    label = _INSTALL_LABELS.get(kind, kind)
    name = _clean(distribution) or "homenet"
    lines = [f"This will uninstall {name} ({label}):", "", _clean(display) or "", ""]
    if purge:
        lines.append("Saved data to remove:")
        for path in paths:
            lines.append(f"  {_clean(path) or ''}")
    else:
        where = _clean(paths[0]) if paths else None
        lines.append(f"Saved data will be kept at {where}.")
    return "\n".join(lines)


def format_uninstall_cancelled() -> str:
    """The user answered no. Nothing was run and nothing was deleted."""
    return "Uninstall cancelled. Nothing was removed."


def format_uninstall_result(
    distribution: str,
    paths: Sequence[str],
    removed: Sequence[str],
    *,
    purge: bool,
) -> str:
    """Text after a successful uninstall. Says whether saved data was kept."""
    name = _clean(distribution) or "homenet"
    lines = [f"Uninstalled {name}."]
    if purge:
        if removed:
            lines.extend(f"Removed {_clean(path) or ''}." for path in removed)
        else:
            where = _clean(paths[0]) if paths else None
            lines.append(f"No saved data was found at {where}.")
    else:
        where = _clean(paths[0]) if paths else None
        lines.append(f"Saved data was kept at {where}.")
    return "\n".join(lines)


def format_uninstall_json(
    *,
    distribution: str,
    kind: str,
    paths: Sequence[str],
    removed: Sequence[str],
    purge: bool,
    cancelled: bool,
    uninstalled: bool,
) -> str:
    """JSON for ``homenet uninstall --json``.

    Shape: ``cancelled``, ``data_kept``, ``data_paths``, ``distribution``,
    ``install``, ``purged``, ``removed_paths``, ``uninstalled``.
    """
    purged = bool(removed) and purge and uninstalled and not cancelled
    return _dumps(
        {
            "cancelled": cancelled,
            "data_kept": not purged,
            "data_paths": [_clean(path) or "" for path in paths],
            "distribution": _clean(distribution) or "",
            "install": _clean(kind) or "",
            "purged": purged,
            "removed_paths": [_clean(path) or "" for path in removed],
            "uninstalled": bool(uninstalled and not cancelled),
        }
    )


def format_explain_json(command: str, commands: Sequence[dict]) -> str:
    """JSON for ``homenet explain <command> --json``.

    Shape: ``{"command": str, "commands": [<command>, ...]}``. Each command
    object is the one :meth:`~homenet.core.commands.Command.to_dict` returns,
    with ``display`` and ``purpose`` already cleaned by the caller.
    """
    return _dumps({"command": _clean(command) or "", "commands": list(commands)})


def merge_commands(document: str, commands: Sequence[dict]) -> str:
    """Add a top-level ``commands`` list to a JSON object.

    Used when ``--show-cmd`` is combined with ``--json``. ``commands`` entries
    use the same shape as :func:`format_explain_json`.
    """
    payload = json.loads(document)
    payload["commands"] = list(commands)
    return _dumps(payload)


def _error_parts(message: str, hint: str | None) -> tuple[str, str | None]:
    return _clean(message) or "Something went wrong.", _clean(hint)


def format_whoami(info: NetInfo) -> str:
    """Table of this computer's address on the home network."""
    rows = (
        ("Interface", _text(info.interface, _NOT_AVAILABLE)),
        ("IP address", _text(info.ip, _NOT_AVAILABLE)),
        ("Gateway", _text(info.gateway, _NOT_AVAILABLE)),
        ("Home network", _text(info.subnet, _NOT_AVAILABLE)),
        ("Network size", _network_size(info)),
    )
    lines = ["This computer on your home network", "", _pairs(rows), "", *_WHOAMI_NOTES]
    if not info.ip:
        lines.extend(["", "This computer's own IP address was not available."])
    if info.wsl_nat:
        network = _clean(info.subnet) or _clean(info.ip)
        lines.extend(["", f"Warning: {wsl_nat_detail(network)}", WSL_NAT_FIX])
    return "\n".join(lines)


def format_devices(devices: Sequence[Device], *, local: NetInfo | None = None) -> str:
    """Table of hosts. One row per device: address, name, MAC, and maker.

    When ``local`` is set, the row for ``local.ip`` is named ``this computer``.
    A missing MAC on that row is filled from ``local.mac``.
    """
    lines = ["Devices on your home network", ""]
    if not devices:
        lines.append("No devices were found.")
        lines.append("")
        lines.append("Make sure this computer is connected to your home network, then try again.")
        return "\n".join(lines)
    ordered = sorted(devices, key=_device_sort_key)
    lines.append(_device_table(ordered, local=local))
    lines.append("")
    count = len(ordered)
    noun = "device" if count == 1 else "devices"
    lines.append(f"{count} {noun} found.")
    return "\n".join(lines)


def format_device(device: Device) -> str:
    """Detail view for one device, including any ports it reported."""
    name = _clean(device.hostname)
    ip = _text(device.ip, _UNKNOWN)
    title = f"{name} ({ip})" if name else f"Device {ip}"
    rows = (
        ("Name", name or _UNKNOWN),
        ("IP address", ip),
        ("MAC address", _text(device.mac, _UNKNOWN)),
        ("Maker", _text(device.vendor, _UNKNOWN)),
    )
    lines = [title, "", _pairs(rows), "", "Ports"]
    if not device.ports:
        lines.append("No ports were reported for this device.")
        return "\n".join(lines)
    port_rows = [
        (
            str(port.number),
            _text(port.protocol, _UNKNOWN),
            _text(port.state, _UNKNOWN),
            _text(port.service, _UNKNOWN),
        )
        for port in sorted(device.ports, key=_port_sort_key)
    ]
    lines.append("")
    lines.append(_render_table(("Number", "Protocol", "State", "What it is"), port_rows))
    lines.append("")
    lines.append("Open means a program is listening on that port.")
    return "\n".join(lines)


def format_diff(diff: DeviceDiff) -> str:
    """What changed since the saved snapshot.

    Sections, in order, are new, missing, changed, and MAC address changed.
    A MAC change at the same IP is flagged as a possible spoof or a replaced
    device. When ``has_changes`` is false, the text says nothing changed.
    """
    if not diff.has_changes:
        return (
            "No changes since your saved snapshot.\n"
            "\n"
            "The devices on your network match the snapshot you saved with `homenet baseline`."
        )
    lines = ["Changes since your saved snapshot", ""]
    if diff.new:
        lines.extend(
            [
                "New",
                "These devices were not in your saved snapshot.",
                "",
                _device_table(diff.new),
                "",
            ]
        )
    if diff.missing:
        lines.extend(
            [
                "Missing",
                "These devices were in your saved snapshot but are not on the network now.",
                "",
                _device_table(diff.missing),
                "",
            ]
        )
    if diff.changed:
        lines.extend(["Changed", "A detail changed on these devices.", ""])
        blocks = [_change_block(old, cur) for old, cur in _sorted_pairs(diff.changed)]
        lines.extend(["\n\n".join(blocks), ""])
    if diff.mac_changed:
        lines.extend(
            [
                "MAC address changed",
                "Same IP address, different MAC address. This may be a spoof or a replaced device.",
                "",
            ]
        )
        blocks = [_mac_block(old, cur) for old, cur in _sorted_pairs(diff.mac_changed)]
        lines.extend(["\n\n".join(blocks), ""])
    lines.append(_diff_summary(diff))
    return "\n".join(lines)


def format_whoami_json(info: NetInfo) -> str:
    """JSON for ``homenet whoami-net --json``. See the module docstring.

    ``ip`` is the address. ``prefix`` remains for callers that already read it.
    ``address_count``, ``range_start``, and ``range_end`` match the size line.
    """
    ip, prefix = _address_prefix(info)
    span = _network_span(info)
    warning = None
    if info.wsl_nat:
        network = _clean(info.subnet) or _clean(info.ip)
        warning = _clean(f"{wsl_nat_detail(network)} {WSL_NAT_FIX}")
    payload = {
        "interface": _clean(info.interface),
        "ip": ip,
        "prefix": prefix,
        "gateway": _clean(info.gateway),
        "subnet": _clean(info.subnet),
        "address_count": None if span is None else span[1],
        "range_start": None if span is None else span[2],
        "range_end": None if span is None else span[3],
        "wsl_nat": bool(info.wsl_nat),
        "warning": warning,
    }
    return _dumps(payload)


def format_devices_json(devices: Sequence[Device], *, local: NetInfo | None = None) -> str:
    """JSON for ``homenet devices --json``. See the module docstring."""
    ordered = sorted(devices, key=_device_sort_key)
    payloads = [_device_payload(device, local=local) for device in ordered]
    return _dumps({"devices": payloads})


def format_device_json(device: Device) -> str:
    """JSON for ``homenet device <ip> --json``. See the module docstring."""
    return _dumps(_device_payload(device))


def format_diff_json(diff: DeviceDiff) -> str:
    """JSON for ``homenet new-devices --json``. See the module docstring."""
    payload = {
        "has_changes": diff.has_changes,
        "new": [_device_payload(device) for device in sorted(diff.new, key=_device_sort_key)],
        "missing": [
            _device_payload(device) for device in sorted(diff.missing, key=_device_sort_key)
        ],
        "changed": [_pair_payload(old, cur) for old, cur in _sorted_pairs(diff.changed)],
        "mac_changed": [_pair_payload(old, cur) for old, cur in _sorted_pairs(diff.mac_changed)],
    }
    return _dumps(payload)


def format_doctor_json(results: Sequence[CheckResult]) -> str:
    """JSON for ``homenet doctor --json``. See the module docstring.

    ``detail`` and ``fix_hint`` can repeat a gateway or interface name from the
    network, so they go through :func:`_clean`.
    """
    payload = {
        "ok": not any(not result.ok and result.severity != "warning" for result in results),
        "checks": [
            {
                "name": result.name,
                "ok": result.ok,
                "severity": result.severity,
                "detail": _clean(result.detail),
                "fix_hint": _clean(result.fix_hint),
            }
            for result in results
        ],
    }
    return _dumps(payload)


def format_ports(device: Device, notes: Sequence[PortNote]) -> str:
    """Open ports with a plain-English risk note for each one."""
    title = _host_heading("Open ports on", device)
    open_ports = _open_ports(device)
    if not open_ports:
        return "\n".join(
            [
                title,
                "",
                "No open ports were found.",
                "",
                "That is normal for phones and many computers. "
                "They usually do not listen for connections.",
            ]
        )
    blocks = [_port_block(port, _find_note(port, notes)) for port in open_ports]
    count = len(open_ports)
    noun = "open port" if count == 1 else "open ports"
    return "\n".join(
        [
            title,
            "",
            "\n\n".join(blocks),
            "",
            f"{count} {noun}.",
            "High means a service that is often attacked. Turn it off if you do not use it.",
            "Medium means be careful, especially with passwords.",
            "Low means this is normal on a home device.",
        ]
    )


def format_ports_json(device: Device, notes: Sequence[PortNote]) -> str:
    """JSON for ``homenet ports <ip> --json``. See the module docstring."""
    payload = {
        "ip": _clean(device.ip),
        "hostname": _clean(device.hostname),
        "ports": [_port_payload(port, _find_note(port, notes)) for port in _open_ports(device)],
    }
    return _dumps(payload)


def format_services(device: Device) -> str:
    """Open services, including the program name and version when known."""
    title = _host_heading("Services on", device)
    open_ports = _open_ports(device)
    if not open_ports:
        return "\n".join(
            [
                title,
                "",
                "No running services were identified.",
                "",
                "Nothing on this device accepted a connection. "
                "That is normal for phones and many computers.",
            ]
        )
    rows = [
        (
            str(port.number),
            _text(port.protocol, _UNKNOWN),
            _text(port.service, _UNKNOWN),
            _text(port.product, _UNKNOWN),
            _text(port.version, _UNKNOWN),
        )
        for port in open_ports
    ]
    return "\n".join(
        [
            title,
            "",
            _render_table(("Number", "Protocol", "Service", "Product", "Version"), rows),
            "",
            "Product is the program. Version is the release, when the scan could tell.",
            "Unknown means the scan could not name it.",
        ]
    )


def format_services_json(device: Device) -> str:
    """JSON for ``homenet services <ip> --json``. See the module docstring."""
    payload = {
        "ip": _clean(device.ip),
        "hostname": _clean(device.hostname),
        "services": [
            {
                "number": port.number,
                "protocol": _clean(port.protocol),
                "state": _clean(port.state),
                "service": _clean(port.service),
                "product": _clean(port.product),
                "version": _clean(port.version),
            }
            for port in _open_ports(device)
        ],
    }
    return _dumps(payload)


def format_router(result: RouterCheck) -> str:
    """What the router admin check found, plus safe next steps."""
    rows = (
        ("Gateway", _text(result.gateway, _UNKNOWN)),
        ("Admin page", "reachable" if result.admin_reachable else "not reachable"),
        ("Plain HTTP", "yes" if result.plain_http_reachable else "no"),
    )
    pages = "\n\n".join(_page_block(page) for page in result.pages)
    lines = ["Your home router", "", _pairs(rows), "", "Pages", "", pages, ""]
    lines.extend(_router_meaning(result))
    return "\n".join(lines)


def format_router_json(result: RouterCheck) -> str:
    """JSON for ``homenet router --json``. See the module docstring."""
    payload = {
        "gateway": _clean(result.gateway),
        "admin_reachable": result.admin_reachable,
        "plain_http_reachable": result.plain_http_reachable,
        "pages": [_page_payload(page) for page in result.pages],
    }
    return _dumps(payload)


def _speed_estimate(result: SpeedResult) -> str:
    """Megabits per second, labeled as an estimate."""
    return _clean(f"about {round(result.download_mbps)} Mbps (estimate)") or ""


def _speed_span(result: SpeedResult) -> str:
    """How many connections ran, and about how long the test took."""
    connections = result.connections
    conn = "connection" if connections == 1 else "connections"
    seconds = round(result.seconds + result.warmup_s)
    unit = "second" if seconds == 1 else "seconds"
    return _clean(f"Used {connections} {conn} over about {seconds} {unit}.") or ""


def _speed_error_note(result: SpeedResult) -> str | None:
    """A one-line count when any connection reported an error."""
    count = len(result.errors)
    if count <= 0:
        return None
    noun = "connection" if count == 1 else "connections"
    return _clean(f"{count} {noun} reported an error.")


def format_speed(result: SpeedResult) -> str:
    """Estimate line, then connections and duration. No WSL note."""
    rows = (("Download speed", _speed_estimate(result)),)
    lines = [_pairs(rows), _speed_span(result)]
    note = _speed_error_note(result)
    if note:
        lines.append(note)
    return "\n".join(lines)


def format_speed_json(result: SpeedResult) -> str:
    """JSON for ``homenet speed --json``. See the module docstring."""
    payload = {
        "download_mbps": result.download_mbps,
        "bytes": result.bytes_read,
        "seconds": result.seconds,
        "url": _clean(result.url),
        "median_mbps": result.median_mbps,
        "connections": result.connections,
        "warmup_s": result.warmup_s,
        "errors": [_clean(item) or "" for item in result.errors],
        "total_bytes": result.total_bytes,
    }
    return _dumps(payload)


_WSL_WIFI = "Wi-Fi info isn't visible inside WSL"
_SIGNAL_UNKNOWN = "unknown (install iw to see signal)"
# Hosts and networks, checked after the gateway and loopback. IPv4 resolvers
# are single addresses; IPv6 resolvers are the provider's allocated range.
_PROVIDER_NETWORKS = (
    (ipaddress.ip_network("1.1.1.1/32"), "Cloudflare (public)"),
    (ipaddress.ip_network("1.0.0.1/32"), "Cloudflare (public)"),
    (ipaddress.ip_network("2606:4700:4700::/48"), "Cloudflare (public)"),
    (ipaddress.ip_network("8.8.8.8/32"), "Google (public)"),
    (ipaddress.ip_network("8.8.4.4/32"), "Google (public)"),
    (ipaddress.ip_network("2001:4860:4860::/48"), "Google (public)"),
    (ipaddress.ip_network("9.9.9.9/32"), "Quad9 (public)"),
    (ipaddress.ip_network("149.112.112.112/32"), "Quad9 (public)"),
    (ipaddress.ip_network("2620:fe::/48"), "Quad9 (public)"),
)
_WIFI_REASONS = {
    "no Wi-Fi interface": "No Wi-Fi adapter was found on this computer.",
    "nmcli/iw not installed": "Wi-Fi tools are not installed. Install iw to see the signal.",
    "not connected": "This computer is not connected to Wi-Fi.",
}


def format_wifi(info: WifiInfo) -> str:
    """Wi-Fi signal, channel, and a one-line explanation of the band."""
    if not info.available:
        message = _wifi_message(info)
        return "\n".join(["Your Wi-Fi", "", message])
    rows: list[tuple[str, str]] = [
        ("Network", _text(info.ssid, _UNKNOWN)),
        ("Interface", _text(info.interface, _UNKNOWN)),
        ("Signal", _signal_label(info)),
    ]
    channel = _channel_value(info)
    if channel:
        rows.append(("Channel", channel))
    if info.link_speed_mbps is not None:
        rows.append(("Link speed", _mbps(info.link_speed_mbps)))
    lines = ["Your Wi-Fi", "", _pairs(rows)]
    note = _band_note(info.band, info.channel)
    if note:
        lines.extend(["", note])
    return "\n".join(lines)


def format_wifi_json(info: WifiInfo) -> str:
    """JSON for ``homenet wifi --json``. See the module docstring."""
    available = bool(info.available)
    payload = {
        "available": available,
        "wsl": bool(info.wsl),
        "reason": _clean(info.reason),
        "message": None if available else _wifi_message(info),
        "interface": _clean(info.interface),
        "ssid": _clean(info.ssid),
        "signal": _signal_label(info) if available else None,
        "signal_dbm": info.signal_dbm,
        "signal_percent": info.signal_percent,
        "channel": info.channel,
        "frequency_mhz": info.frequency_mhz,
        "band": _clean(info.band),
        "band_note": _band_note(info.band, info.channel) if available else None,
        "link_speed_mbps": info.link_speed_mbps,
    }
    return _dumps(payload)


def format_dns(
    config: DnsConfig, lookup: LookupResult, gateway: str | None = None, *, wsl: bool = False
) -> str:
    """DNS servers, who they likely belong to, and one lookup line."""
    lines = ["DNS servers", ""]
    if not config.servers:
        lines.append("No DNS servers were found.")
    else:
        rows = [
            (_show_ip(server.ip), _server_label(server.ip, gateway, wsl))
            for server in config.servers
        ]
        lines.append(_render_table(("Server", "Who it is"), rows))
        upstream = _upstream_line(config, gateway, wsl)
        if upstream:
            lines.extend(["", upstream])
    lines.extend(["", _lookup_line(lookup)])
    return "\n".join(lines)


def format_dns_json(
    config: DnsConfig, lookup: LookupResult, gateway: str | None = None, *, wsl: bool = False
) -> str:
    """JSON for ``homenet dns --json``. See the module docstring."""
    local = any(_is_loopback(server.ip) for server in config.servers)
    payload = {
        "gateway": _canonical(gateway),
        "source": _clean(config.source),
        "uses_systemd_stub": bool(config.uses_systemd_stub),
        "servers": [
            {
                "ip": _canonical(server.ip) or _clean(server.ip),
                "source": _clean(server.source),
                "interface": _clean(server.interface),
                "label": _server_label(server.ip, gateway, wsl),
            }
            for server in config.servers
        ],
        "upstream": _upstream_payload(config, gateway, wsl) if local else [],
        "lookup": _lookup_payload(lookup),
    }
    return _dumps(payload)


def _signal_word(dbm: int) -> str:
    """Excellent >= -50, Good >= -60, Fair >= -70, otherwise Weak."""
    if dbm >= -50:
        return "Excellent"
    if dbm >= -60:
        return "Good"
    if dbm >= -70:
        return "Fair"
    return "Weak"


def _signal_label(info: WifiInfo) -> str:
    """Words plus dBm, or the same words for a percent, or the iw hint."""
    if info.signal_dbm is not None:
        word = _signal_word(info.signal_dbm)
        text = f"{word} ({info.signal_dbm} dBm)"
    elif info.signal_percent is not None:
        word = _signal_word(percent_to_dbm(info.signal_percent))
        text = f"{word} ({info.signal_percent}%)"
    else:
        text = _SIGNAL_UNKNOWN
    return _clean(text) or _SIGNAL_UNKNOWN


def _wifi_message(info: WifiInfo) -> str:
    if info.wsl or info.reason == "WSL":
        return _clean(_WSL_WIFI) or _WSL_WIFI
    mapped = _WIFI_REASONS.get(info.reason or "")
    if mapped:
        iface = _clean(info.interface)
        if info.reason == "not connected" and iface:
            mapped = f"{mapped[:-1]} on {iface}."
        return _clean(mapped) or "Wi-Fi isn't available."
    reason = _clean(info.reason)
    if reason:
        return _clean(f"Wi-Fi isn't available ({reason}).") or "Wi-Fi isn't available."
    return "Wi-Fi isn't available."


def _band_note(band: str | None, channel: int | None) -> str | None:
    """One line on how far this band reaches compared with the other."""
    name = _clean(band)
    if name == "2.4 GHz":
        detail = (
            "2.4 GHz reaches farther through walls, and 5 GHz is faster but has a shorter range"
        )
    elif name == "5 GHz":
        detail = "5 GHz is faster but has a shorter range, and 2.4 GHz reaches farther"
    elif name == "6 GHz":
        detail = "6 GHz is faster but has a shorter range, and 2.4 GHz reaches farther"
    else:
        return None
    if channel is None:
        return _clean(f"{detail}.")
    return _clean(f"Channel {channel} is on {name}. {detail}.")


def _channel_value(info: WifiInfo) -> str | None:
    band = _clean(info.band)
    if info.channel is None:
        return band
    if band:
        return _clean(f"{info.channel} ({band})")
    return _clean(str(info.channel))


def _mbps(value: float) -> str:
    number = f"{value:.1f}".rstrip("0").rstrip(".")
    return _clean(f"{number} Mb/s") or _UNKNOWN


def _address(value: str | None) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Parsed IP, or None when the text is empty or not an address."""
    text = _clean(value)
    if not text:
        return None
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def _canonical(value: str | None) -> str | None:
    """Printable IP text in canonical form, or None when it is not an IP."""
    address = _address(value)
    return None if address is None else str(address)


def _show_ip(value: str | None) -> str:
    return _canonical(value) or _text(value, _UNKNOWN)


def _is_loopback(value: str | None) -> bool:
    address = _address(value)
    return address is not None and address.is_loopback


def _provider_label(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    for network, label in _PROVIDER_NETWORKS:
        if address.version == network.version and address in network:
            return label
    return None


_WSL_DNS_RELAY = ipaddress.ip_address("10.255.255.254")


def _server_label(ip: str | None, gateway: str | None, wsl: bool = False) -> str:
    """Who this DNS server likely belongs to.

    Order: gateway, loopback, provider range, private or link-local, then any
    other global address. The gateway wins even when it is also a public resolver.
    """
    address = _address(ip)
    gateway_address = _address(gateway)
    if address is not None and address == gateway_address:
        label = "your router"
    elif address is not None and address.is_loopback:
        label = "this computer (local resolver)"
    elif wsl and address == _WSL_DNS_RELAY:
        label = "WSL's built-in DNS relay (forwards to Windows)"
    elif address is not None and (provider := _provider_label(address)):
        label = provider
    elif address is not None and (address.is_private or address.is_link_local):
        label = "a device on your network"
    else:
        label = "likely your internet provider"
    return _clean(label) or "likely your internet provider"


def _upstream_pairs(
    config: DnsConfig, gateway: str | None, wsl: bool = False
) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    seen: set[str] = set()
    for raw in config.upstream:
        ip = _canonical(raw)
        if not ip or _is_loopback(ip) or ip in seen:
            continue
        seen.add(ip)
        pairs.append((ip, _server_label(ip, gateway, wsl)))
    return pairs


def _upstream_line(config: DnsConfig, gateway: str | None, wsl: bool = False) -> str | None:
    if not any(_is_loopback(server.ip) for server in config.servers):
        return None
    pairs = _upstream_pairs(config, gateway, wsl)
    if not pairs:
        return None
    shown = ", ".join(f"{ip} ({label})" for ip, label in pairs)
    return _clean(f"Upstream servers: {shown}.")


def _upstream_payload(config: DnsConfig, gateway: str | None, wsl: bool = False) -> list[dict]:
    return [{"ip": ip, "label": label} for ip, label in _upstream_pairs(config, gateway, wsl)]


def _ip_family(value: str) -> str:
    address = _address(value)
    if address is None:
        return "address"
    return "IPv6" if address.version == 6 else "IPv4"


def _lookup_line(lookup: LookupResult) -> str:
    name = _clean(lookup.name) or "the name"
    if lookup.elapsed_ms is None:
        timing = ""
    else:
        timing = f" in {lookup.elapsed_ms:g} ms"
    if lookup.ok:
        addresses = [item for item in (_clean(addr) for addr in lookup.addresses) if item]
        if addresses:
            shown = ", ".join(f"{addr} ({_ip_family(addr)})" for addr in addresses)
            text = f"Lookup of {name} succeeded{timing}. It returned: {shown}."
        else:
            text = f"Lookup of {name} succeeded{timing}."
    else:
        error = _clean(lookup.error) or "it did not answer"
        text = f"Lookup of {name} failed{timing}: {error}."
    return _clean(text) or "Lookup failed."


def _lookup_payload(lookup: LookupResult) -> dict:
    addresses = [item for item in (_clean(addr) for addr in lookup.addresses) if item]
    return {
        "name": _clean(lookup.name),
        "ok": bool(lookup.ok),
        "addresses": addresses,
        "elapsed_ms": lookup.elapsed_ms,
        "error": _clean(lookup.error),
        "summary": _lookup_line(lookup),
    }


def _host_heading(prefix: str, device: Device) -> str:
    ip = _text(device.ip, _UNKNOWN)
    name = _clean(device.hostname)
    if name:
        return f"{prefix} {name} ({ip})"
    return f"{prefix} {ip}"


def _open_ports(device: Device) -> list[Port]:
    return sorted((port for port in device.ports if port.state == "open"), key=_port_sort_key)


def _find_note(port: Port, notes: Sequence[PortNote]) -> PortNote | None:
    proto = (port.protocol or "tcp").lower()
    for note in notes:
        if note.port == port.number and note.protocol.lower() == proto:
            return note
    return None


def _port_block(port: Port, note: PortNote | None) -> str:
    name = _clean(note.name) if note else _clean(port.service)
    risk = _clean(note.risk) if note else "medium"
    text = _clean(note.note) if note else _clean(GENERIC_NOTE)
    proto = _text(port.protocol, _UNKNOWN)
    return (
        f"{port.number}/{proto}  {name or _UNKNOWN}  risk: {risk or _UNKNOWN}\n  {text or _UNKNOWN}"
    )


def _port_payload(port: Port, note: PortNote | None) -> dict:
    name = _clean(note.name) if note else _clean(port.service)
    risk = _clean(note.risk) if note else "medium"
    text = _clean(note.note) if note else _clean(GENERIC_NOTE)
    return {
        "number": port.number,
        "protocol": _clean(port.protocol),
        "state": _clean(port.state),
        "service": _clean(port.service),
        "name": name,
        "risk": risk,
        "note": text,
    }


def _page_block(page: AdminPage) -> str:
    url = _text(page.url, _UNKNOWN)
    if not page.reachable:
        reason = _clean(page.error) or "no reply"
        return f"{url}\n  Not reachable ({reason})."
    lines = [
        url,
        f"  Status  {page.status if page.status is not None else _UNKNOWN}",
        f"  Title   {_text(page.title, _UNKNOWN)}",
        f"  Server  {_text(page.server, _UNKNOWN)}",
    ]
    if page.plain_http:
        lines.append("  Plain HTTP: a password typed here is not encrypted.")
    else:
        lines.append("  HTTPS: the page is encrypted.")
    return "\n".join(lines)


def _page_payload(page: AdminPage) -> dict:
    return {
        "url": _clean(page.url),
        "port": page.port,
        "reachable": page.reachable,
        "plain_http": page.plain_http,
        "status": page.status,
        "title": _clean(page.title),
        "server": _clean(page.server),
        "error": _clean(page.error),
    }


def _router_meaning(result: RouterCheck) -> list[str]:
    lines = ["What this means", ""]
    if not result.admin_reachable:
        lines.append(
            "No admin page answered on ports 80, 443, or 8080. That is common. "
            "The page may be turned off, or it may use a different port."
        )
    else:
        lines.append(
            "An admin page answered. Anyone on your home network can try to open it in a browser."
        )
        if result.plain_http_reachable:
            lines.append(
                "At least one page is plain HTTP. A password typed there can be read "
                "on your network."
            )
        else:
            lines.append("The page that answered uses HTTPS, so the login is encrypted.")
    lines.append("")
    lines.extend(_router_steps(result))
    return lines


def _router_steps(result: RouterCheck) -> list[str]:
    lines = ["Safe next steps"]
    if not result.admin_reachable:
        lines.append("- Check the gateway with `homenet whoami-net`.")
        lines.append("- Look up your router model for its admin address. Do not guess passwords.")
    else:
        lines.append("- Open the page only if you recognise it as your router.")
        if result.plain_http_reachable:
            https = any(page.reachable and not page.plain_http for page in result.pages)
            if https:
                lines.append(
                    "- Prefer the HTTPS address when you sign in. "
                    "Do not type the password on the HTTP page."
                )
            else:
                lines.append("- Do not type the router password on a page that is not HTTPS.")
        lines.append(
            "- If the password is still the one printed on the router, change it after you sign in."
        )
    lines.append("- This check only requested the page. It did not log in.")
    return lines


def _dumps(payload: object) -> str:
    """Stable JSON. ``json.dumps`` escapes every string; keys are sorted."""
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True)


def _device_payload(device: Device, *, local: NetInfo | None = None) -> dict:
    payload = {
        "ip": _clean(device.ip),
        "hostname": _clean(device.hostname),
        "mac": _clean(_source_mac(device, local)),
        "vendor": _clean(device.vendor),
        "ports": [
            {
                "number": port.number,
                "protocol": _clean(port.protocol),
                "state": _clean(port.state),
                "service": _clean(port.service),
            }
            for port in sorted(device.ports, key=_port_sort_key)
        ],
    }
    if _is_self(device, local):
        payload["is_self"] = True
    return payload


def _pair_payload(old: Device, current: Device) -> dict:
    return {"before": _device_payload(old), "after": _device_payload(current)}


def _device_table(devices: Sequence[Device], *, local: NetInfo | None = None) -> str:
    rows = [
        (
            _text(device.ip, _UNKNOWN),
            _row_name(device, local),
            _row_mac(device, local),
            _text(device.vendor, _UNKNOWN),
        )
        for device in sorted(devices, key=_device_sort_key)
    ]
    return _render_table(("IP address", "Name", "MAC address", "Maker"), rows)


def _is_self(device: Device, local: NetInfo | None) -> bool:
    """True when ``device`` is the computer ``local`` describes."""
    if local is None:
        return False
    return _same_ip(device.ip, local.ip)


def _same_ip(left: str | None, right: str | None) -> bool:
    if not left or not right:
        return False
    try:
        return ipaddress.ip_address(str(left).strip()) == ipaddress.ip_address(str(right).strip())
    except ValueError:
        return False


def _row_name(device: Device, local: NetInfo | None) -> str:
    if _is_self(device, local):
        return _clean("this computer") or _UNKNOWN
    return _text(device.hostname, _UNKNOWN)


def _source_mac(device: Device, local: NetInfo | None) -> str | None:
    """Scan MAC, or this computer's MAC when the scan left it blank."""
    if _is_self(device, local) and not _clean(device.mac) and local is not None:
        return local.mac
    return device.mac


def _row_mac(device: Device, local: NetInfo | None) -> str:
    return _text(_source_mac(device, local), _UNKNOWN)


def _sorted_pairs(pairs: Sequence[tuple[Device, Device]]) -> list[tuple[Device, Device]]:
    return sorted(pairs, key=lambda pair: _device_sort_key(pair[1]))


def _change_block(old: Device, current: Device) -> str:
    title_name = _clean(current.hostname)
    ip = _text(current.ip, _UNKNOWN)
    title = f"{title_name} ({ip})" if title_name else f"Device {ip}"
    rows: list[tuple[str, str]] = []
    for label, before, after in (
        ("IP address", old.ip, current.ip),
        ("Name", old.hostname, current.hostname),
        ("MAC address", old.mac, current.mac),
        ("Maker", old.vendor, current.vendor),
    ):
        if label == "MAC address" and normalize_mac(before) == normalize_mac(after):
            continue
        before_text = _text(before, _UNKNOWN)
        after_text = _text(after, _UNKNOWN)
        if before_text != after_text:
            rows.append((label, f"was {before_text}, now {after_text}"))
    before_ports = _ports_summary(old.ports)
    after_ports = _ports_summary(current.ports)
    if before_ports != after_ports:
        rows.append(("Ports", f"was {before_ports}, now {after_ports}"))
    if not rows:
        rows.append(("Details", "changed"))
    return f"{title}\n\n{_pairs(rows)}"


def _mac_block(old: Device, current: Device) -> str:
    ip = _text(current.ip or old.ip, _UNKNOWN)
    return "\n".join(
        [
            ip,
            "  Possible spoof or replaced device.",
            f"  Was  {_mac_label(old)}",
            f"  Now  {_mac_label(current)}",
        ]
    )


def _mac_label(device: Device) -> str:
    name = _clean(device.hostname) or _clean(device.vendor) or _UNKNOWN
    return f"{_text(device.mac, _UNKNOWN)}  {name}"


def _ports_summary(ports: Sequence[Port]) -> str:
    if not ports:
        return "none reported"
    bits: list[str] = []
    for port in sorted(ports, key=_port_sort_key):
        protocol = _text(port.protocol, _UNKNOWN)
        state = _text(port.state, _UNKNOWN)
        service = _clean(port.service)
        bit = f"{port.number}/{protocol} {state}"
        if service:
            bit += f" ({service})"
        bits.append(bit)
    return ", ".join(bits)


def _diff_summary(diff: DeviceDiff) -> str:
    parts: list[str] = []
    if diff.new:
        parts.append(_noun(len(diff.new), "new device", "new devices"))
    if diff.missing:
        parts.append(_noun(len(diff.missing), "missing device", "missing devices"))
    if diff.changed:
        parts.append(_noun(len(diff.changed), "changed device", "changed devices"))
    if diff.mac_changed:
        count = len(diff.mac_changed)
        noun = "MAC address changed" if count == 1 else "MAC addresses changed"
        parts.append(f"{count} {noun}")
    return ". ".join(parts) + "."


def _noun(count: int, singular: str, plural: str) -> str:
    return f"{count} {singular if count == 1 else plural}"


def _address_prefix(info: NetInfo) -> tuple[str | None, int | None]:
    """Cleaned address and the subnet prefix length.

    The prefix is set only when the subnet parses and uses the same IP version.
    """
    ip = _clean(info.ip)
    subnet = _clean(info.subnet)
    if not ip or not subnet:
        return ip, None
    try:
        host = ipaddress.ip_address(ip)
        network = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        return ip, None
    if host.version != network.version:
        return ip, None
    return ip, network.prefixlen


def _network_span(info: NetInfo) -> tuple[int, int, str, str] | None:
    """``(prefix, address count, first, last)`` for ``info.subnet``, or None."""
    subnet = _clean(info.subnet)
    if not subnet:
        return None
    try:
        network = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        return None
    start = _clean(str(network.network_address))
    end = _clean(str(network.broadcast_address))
    if not start or not end:
        return None
    return network.prefixlen, network.num_addresses, start, end


def _network_size(info: NetInfo) -> str:
    """Plain-English size of the subnet, or ``not available``."""
    span = _network_span(info)
    if span is None:
        return _NOT_AVAILABLE
    prefix, count, start, end = span
    noun = "address" if count == 1 else "addresses"
    text = f"/{prefix} ({count:,} {noun}: {start}\u2013{end})"
    return _clean(text) or _NOT_AVAILABLE


_clean = clean_text  # one shared sanitiser; see homenet.core._text


def _text(value: str | None, missing: str) -> str:
    return _clean(value) or missing


def _pairs(rows: Sequence[tuple[str, str]]) -> str:
    width = max(len(label) for label, _value in rows)
    return "\n".join(f"{label:<{width}}  {value}" for label, value in rows)


def _render_table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> str:
    widths = [len(header) for header in headers]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))
    lines: list[str] = []
    for cells in (headers, *rows):
        padded = [cell.ljust(widths[index]) for index, cell in enumerate(cells)]
        lines.append("  ".join(padded).rstrip())
    return "\n".join(lines)


def _device_sort_key(device: Device) -> tuple[int, int | str]:
    try:
        address = ipaddress.ip_address(device.ip)
    except ValueError:
        return (2, device.ip)
    return (0 if address.version == 4 else 1, int(address))


def _port_sort_key(port: Port) -> tuple[int, str]:
    return (port.number, port.protocol)

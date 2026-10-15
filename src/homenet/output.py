"""Plain-text and JSON views for the homenet CLI.

These functions only turn core data into text. They do not scan, print, or exit,
and they do not spawn system commands.

Input shapes for Net Core to match:

* :func:`format_whoami` takes one :class:`homenet.core.netinfo.NetInfo`.
  Fields it reads: ``interface``, ``ip``, ``gateway``, ``subnet``.
  ``NetInfo`` has no MAC address, so this view does not show one.
* :func:`format_devices` takes a sequence of :class:`homenet.core.parser.Device`
  (the host list for ``homenet devices``).
* :func:`format_device` takes one :class:`homenet.core.parser.Device`
  (the detail view for ``homenet device <ip>``), including its ``ports``
  list of :class:`homenet.core.parser.Port` (``number``, ``protocol``,
  ``state``, ``service``).
* :func:`format_diff` takes one :class:`homenet.core.baseline.DeviceDiff`
  (``new``, ``missing``, ``changed``, ``mac_changed``, ``has_changes``).

Missing device fields (``hostname``, ``mac``, ``vendor``, ``service``) are
shown as ``unknown``. Missing network fields are shown as ``not available``.

``--json`` shapes (keys sorted, ``null`` for a missing string). Every string
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

    {"gateway": str|null, "interface": str|null, "ip": str|null, "subnet": str|null}

``homenet doctor --json``::

    {"checks": [{"detail": str|null, "fix_hint": str|null, "name": str,
                 "ok": bool, "severity": "ok"|"warning"|"error"}, ...],
     "ok": bool}

``<device>``::

    {"hostname": str|null, "ip": str|null, "mac": str|null,
     "ports": [{"number": int, "protocol": str|null, "service": str|null,
                "state": str|null}, ...],
     "vendor": str|null}

``doctor`` ``ok`` is false only when a check failed at error severity.
Warnings leave it true. ``new-devices`` exits 0 when ``has_changes`` is false,
1 when it is true, and 2 when the command fails.

``--json`` errors are a JSON object on stderr::

    {"error": str, "fix_hint": str|null}
"""

from __future__ import annotations

import ipaddress
import json
from collections.abc import Sequence

from homenet.core._text import clean_text
from homenet.core.baseline import DeviceDiff
from homenet.core.checks import CheckResult
from homenet.core.devices import normalize_mac
from homenet.core.netinfo import NetInfo
from homenet.core.parser import Device, Port

_UNKNOWN = "unknown"
_NOT_AVAILABLE = "not available"

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


def _error_parts(message: str, hint: str | None) -> tuple[str, str | None]:
    return _clean(message) or "Something went wrong.", _clean(hint)


def format_whoami(info: NetInfo) -> str:
    """Table of this computer's address on the home network."""
    rows = (
        ("Interface", _text(info.interface, _NOT_AVAILABLE)),
        ("IP address", _ip_with_prefix(info)),
        ("Gateway", _text(info.gateway, _NOT_AVAILABLE)),
        ("Home network", _text(info.subnet, _NOT_AVAILABLE)),
    )
    lines = ["This computer on your home network", "", _pairs(rows), "", *_WHOAMI_NOTES]
    if not info.ip:
        lines.extend(["", "This computer's own IP address was not available."])
    return "\n".join(lines)


def format_devices(devices: Sequence[Device]) -> str:
    """Table of hosts. One row per device: address, name, MAC, and maker."""
    lines = ["Devices on your home network", ""]
    if not devices:
        lines.append("No devices were found.")
        lines.append("")
        lines.append("Make sure this computer is connected to your home network, then try again.")
        return "\n".join(lines)
    ordered = sorted(devices, key=_device_sort_key)
    lines.append(_device_table(ordered))
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
    """JSON for ``homenet whoami-net --json``. See the module docstring."""
    payload = {
        "interface": _clean(info.interface),
        "ip": _clean(info.ip),
        "gateway": _clean(info.gateway),
        "subnet": _clean(info.subnet),
    }
    return _dumps(payload)


def format_devices_json(devices: Sequence[Device]) -> str:
    """JSON for ``homenet devices --json``. See the module docstring."""
    ordered = sorted(devices, key=_device_sort_key)
    return _dumps({"devices": [_device_payload(device) for device in ordered]})


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


def _dumps(payload: object) -> str:
    """Stable JSON. ``json.dumps`` escapes every string; keys are sorted."""
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True)


def _device_payload(device: Device) -> dict:
    return {
        "ip": _clean(device.ip),
        "hostname": _clean(device.hostname),
        "mac": _clean(device.mac),
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


def _pair_payload(old: Device, current: Device) -> dict:
    return {"before": _device_payload(old), "after": _device_payload(current)}


def _device_table(devices: Sequence[Device]) -> str:
    rows = [
        (
            _text(device.ip, _UNKNOWN),
            _text(device.hostname, _UNKNOWN),
            _text(device.mac, _UNKNOWN),
            _text(device.vendor, _UNKNOWN),
        )
        for device in sorted(devices, key=_device_sort_key)
    ]
    return _render_table(("IP address", "Name", "MAC address", "Maker"), rows)


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


def _ip_with_prefix(info: NetInfo) -> str:
    """Show ``address/prefix`` when the subnet uses the same IP version."""
    if not info.ip:
        return _NOT_AVAILABLE
    shown = _text(info.ip, _NOT_AVAILABLE)
    if not info.subnet:
        return shown
    try:
        host = ipaddress.ip_address(info.ip)
        network = ipaddress.ip_network(info.subnet, strict=False)
    except ValueError:
        return shown
    if host.version != network.version:
        return shown
    return _text(f"{info.ip}/{network.prefixlen}", _NOT_AVAILABLE)


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

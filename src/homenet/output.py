"""Plain-text views for the homenet CLI.

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

Missing device fields (``hostname``, ``mac``, ``vendor``, ``service``) are
shown as ``unknown``. Missing network fields are shown as ``not available``.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Sequence

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
    """What went wrong, plus a fix when one is known."""
    if hint:
        return f"{message}\nFix: {hint}"
    return message


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
    rows = [
        (
            _text(device.ip, _UNKNOWN),
            _text(device.hostname, _UNKNOWN),
            _text(device.mac, _UNKNOWN),
            _text(device.vendor, _UNKNOWN),
        )
        for device in ordered
    ]
    lines.append(_render_table(("IP address", "Name", "MAC address", "Maker"), rows))
    lines.append("")
    count = len(ordered)
    noun = "device" if count == 1 else "devices"
    lines.append(f"{count} {noun} found.")
    return "\n".join(lines)


def format_device(device: Device) -> str:
    """Detail view for one device, including any ports it reported."""
    name = _clean(device.hostname)
    title = f"{name} ({device.ip})" if name else f"Device {device.ip}"
    rows = (
        ("Name", name or _UNKNOWN),
        ("IP address", _text(device.ip, _UNKNOWN)),
        ("MAC address", _text(device.mac, _UNKNOWN)),
        ("Maker", _text(device.vendor, _UNKNOWN)),
    )
    lines = [title, "", _pairs(rows), "", "Ports"]
    if not device.ports:
        lines.append("No ports were reported for this device.")
        return "\n".join(lines)
    port_rows = [
        (str(port.number), port.protocol, port.state, _text(port.service, _UNKNOWN))
        for port in sorted(device.ports, key=_port_sort_key)
    ]
    lines.append("")
    lines.append(_render_table(("Number", "Protocol", "State", "What it is"), port_rows))
    lines.append("")
    lines.append("Open means a program is listening on that port.")
    return "\n".join(lines)


def _ip_with_prefix(info: NetInfo) -> str:
    """Show ``address/prefix`` when the subnet uses the same IP version."""
    if not info.ip:
        return _NOT_AVAILABLE
    if not info.subnet:
        return info.ip
    try:
        host = ipaddress.ip_address(info.ip)
        network = ipaddress.ip_network(info.subnet, strict=False)
    except ValueError:
        return info.ip
    if host.version != network.version:
        return info.ip
    return f"{info.ip}/{network.prefixlen}"


def _clean(value: str | None) -> str | None:
    """Trim surrounding space and replace non-printable characters with ``?``.

    Hostnames, vendors, and other device strings are untrusted network data.
    ESC/CSI/OSC sequences, C0 and C1 controls, newlines, and similar characters
    are turned into a visible ``?`` so they cannot change the terminal.
    """
    if value is None:
        return None
    visible = "".join(char if char.isprintable() else "?" for char in value)
    stripped = visible.strip()
    return stripped or None


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

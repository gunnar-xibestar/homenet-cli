"""Plain-text and JSON views for the homenet CLI.

These functions only turn core data into text. They do not scan, print, or exit,
and they do not spawn system commands.

Input shapes for Net Core to match:

* :func:`format_whoami` takes one :class:`homenet.core.netinfo.NetInfo`.
  Fields it reads: ``interface``, ``ip``, ``gateway``, ``subnet``, ``wsl_nat``.
  ``NetInfo`` has no MAC address, so this view does not show one.
  When ``wsl_nat`` is true, the plain view adds a warning that this may be the
  WSL virtual network, not the home LAN.
* :func:`format_devices` takes a sequence of :class:`homenet.core.parser.Device`
  (the host list for ``homenet devices``).
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

    {"gateway": str|null, "interface": str|null, "ip": str|null,
     "prefix": int|null, "subnet": str|null, "warning": str|null,
     "wsl_nat": bool}

``ip`` is the address. ``prefix`` is the integer length the plain view shows
after it (``address/prefix``). ``prefix`` is null when that line has no prefix.
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

    {"bytes": int, "download_mbps": number, "seconds": number, "url": str|null}

``doctor`` ``ok`` is false only when a check failed at error severity.
Warnings leave it true. ``new-devices`` exits 0 when ``has_changes`` is false,
1 when it is true, and 2 when the command fails.
``ports``, ``services``, ``router``, and ``speed`` exit 0 on success and 1
when the command fails. No open ports, and a router with no admin page, are
still success. Argparse usage errors exit 2.

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
from homenet.core.netinfo import NetInfo
from homenet.core.parser import Device, Port
from homenet.core.port_notes import GENERIC_NOTE, PortNote
from homenet.core.router import AdminPage, RouterCheck
from homenet.core.speed import SpeedResult
from homenet.core.wsl import WSL_NAT_FIX, wsl_nat_detail

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
        ("IP address", _ip_with_prefix(info)),
        ("Gateway", _text(info.gateway, _NOT_AVAILABLE)),
        ("Home network", _text(info.subnet, _NOT_AVAILABLE)),
    )
    lines = ["This computer on your home network", "", _pairs(rows), "", *_WHOAMI_NOTES]
    if not info.ip:
        lines.extend(["", "This computer's own IP address was not available."])
    if info.wsl_nat:
        network = _clean(info.subnet) or _clean(info.ip)
        lines.extend(["", f"Warning: {wsl_nat_detail(network)}", WSL_NAT_FIX])
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
    """JSON for ``homenet whoami-net --json``. See the module docstring.

    ``ip`` and ``prefix`` are the same address and length the plain view shows.
    """
    ip, prefix = _address_prefix(info)
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
        "wsl_nat": bool(info.wsl_nat),
        "warning": warning,
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


def format_speed(result: SpeedResult) -> str:
    """Plain numbers for one short download sample."""
    rows = (
        ("Download", f"{result.download_mbps:.2f} Mb/s"),
        ("Sample", f"{result.bytes_read} bytes"),
        ("Time", f"{result.seconds:.3f} seconds"),
        ("From", "Cloudflare (speed.cloudflare.com)"),
    )
    return "\n".join(
        [
            "Internet download speed",
            "",
            _pairs(rows),
            "",
            "This is a short download from Cloudflare (speed.cloudflare.com), "
            "not a full speed test.",
            "Wi-Fi and other devices in your home can make this lower than your plan.",
            "Mb/s means megabits per second, the unit internet plans use.",
        ]
    )


def format_speed_json(result: SpeedResult) -> str:
    """JSON for ``homenet speed --json``. See the module docstring."""
    payload = {
        "download_mbps": result.download_mbps,
        "bytes": result.bytes_read,
        "seconds": result.seconds,
        "url": _clean(result.url),
    }
    return _dumps(payload)


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


def _address_prefix(info: NetInfo) -> tuple[str | None, int | None]:
    """Cleaned address and the prefix length plain text appends to it.

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


def _ip_with_prefix(info: NetInfo) -> str:
    """Show ``address/prefix`` when the subnet uses the same IP version."""
    ip, prefix = _address_prefix(info)
    if not ip:
        return _NOT_AVAILABLE
    if prefix is None:
        return ip
    return f"{ip}/{prefix}"


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

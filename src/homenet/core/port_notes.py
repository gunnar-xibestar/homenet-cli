"""Plain-English notes and a risk level for common ports. Pure data, never prints."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

RISK_LEVELS = ("low", "medium", "high")


@dataclass(frozen=True)
class PortNote:
    port: int
    protocol: str
    name: str
    risk: str  # "low" | "medium" | "high"
    note: str


# (port, protocol) -> (name, risk, note)
_NOTES: dict[tuple[int, str], tuple[str, str, str]] = {
    (21, "tcp"): ("FTP", "high", "Old file-transfer service; passwords travel unencrypted."),
    (22, "tcp"): (
        "SSH",
        "medium",
        "Remote login. Fine if you use it; use keys or strong "
        "passwords, and don't expose it to the internet.",
    ),
    (23, "tcp"): (
        "Telnet",
        "high",
        "Unencrypted remote login. Turn it off; it's a common way IoT devices get hacked.",
    ),
    (25, "tcp"): ("SMTP", "medium", "Mail server. Unusual on a home device."),
    (53, "tcp"): ("DNS", "low", "Name lookups; normal on your router."),
    (53, "udp"): ("DNS", "low", "Name lookups; normal on your router."),
    (80, "tcp"): (
        "HTTP",
        "medium",
        "Web page without encryption, often a device's admin "
        "page. Avoid entering passwords over it.",
    ),
    (139, "tcp"): (
        "NetBIOS",
        "medium",
        "Old Windows file sharing. Only expected on PCs or NAS boxes.",
    ),
    (443, "tcp"): ("HTTPS", "low", "Encrypted web page, often a device's admin page."),
    (445, "tcp"): (
        "SMB",
        "high",
        "Windows/Samba file sharing. OK on a NAS you trust; never expose it to the internet.",
    ),
    (548, "tcp"): ("AFP", "medium", "Apple file sharing."),
    (631, "tcp"): ("IPP", "low", "Printer service."),
    (1883, "tcp"): ("MQTT", "medium", "Smart-home messaging; often has no password."),
    (1900, "udp"): (
        "UPnP",
        "medium",
        "Lets apps open router ports automatically. Consider turning UPnP off on your router.",
    ),
    (1900, "tcp"): (
        "UPnP",
        "medium",
        "Lets apps open router ports automatically. Consider turning UPnP off on your router.",
    ),
    (3389, "tcp"): (
        "RDP",
        "high",
        "Windows Remote Desktop. A frequent attack target; keep it off unless you need it.",
    ),
    (5000, "tcp"): ("UPnP/web", "medium", "Often a NAS or UPnP web interface."),
    (5353, "udp"): ("mDNS", "low", "Device discovery (AirPlay, printers); normal."),
    (5900, "tcp"): ("VNC", "high", "Remote screen sharing; often weakly protected."),
    (8080, "tcp"): (
        "HTTP-alt",
        "medium",
        "Alternative web port, often an admin page or app without encryption.",
    ),
    (8443, "tcp"): ("HTTPS-alt", "low", "Alternative encrypted web/admin page."),
    (9100, "tcp"): ("Printer", "low", "Raw printing port; normal on printers."),
}

# Fallback by nmap service name when the port number isn't in the table.
_BY_SERVICE: dict[str, tuple[int, str]] = {
    "ssh": (22, "tcp"),
    "telnet": (23, "tcp"),
    "http": (80, "tcp"),
    "https": (443, "tcp"),
    "microsoft-ds": (445, "tcp"),
    "ms-wbt-server": (3389, "tcp"),
    "vnc": (5900, "tcp"),
    "upnp": (1900, "udp"),
    "ftp": (21, "tcp"),
    "http-proxy": (8080, "tcp"),
}

GENERIC_NOTE = (
    "An open port we don't have a note for. If you don't recognise the device or app, "
    "look it up or turn the service off."
)


def note_for(port: int, protocol: str = "tcp", service: str | None = None) -> PortNote:
    """Return the note for ``port``/``protocol``, then by ``service`` name, else generic."""
    proto = (protocol or "tcp").lower()
    entry = _NOTES.get((port, proto))
    if entry is None and service:
        key = _BY_SERVICE.get(service.lower())
        entry = _NOTES.get(key) if key else None
    if entry is None:
        return PortNote(port, proto, service or "unknown", "medium", GENERIC_NOTE)
    name, risk, note = entry
    return PortNote(port, proto, name, risk, note)


def notes_for_ports(ports: Iterable) -> list[PortNote]:
    """Notes for the open ports in ``ports`` (parser ``Port`` objects)."""
    return [note_for(p.number, p.protocol, p.service) for p in ports if p.state == "open"]

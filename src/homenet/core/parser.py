"""Parse nmap ``-oX`` XML into :class:`Device` objects. Never prints."""

from __future__ import annotations

import xml.etree.ElementTree as ET  # noqa: S405 - DTD/entities rejected below
from dataclasses import dataclass, field


class ParseError(Exception):
    """nmap output could not be understood. ``hint`` is a beginner-friendly fix."""

    def __init__(self, message: str, hint: str | None = None) -> None:
        super().__init__(message)
        self.hint = hint


@dataclass(frozen=True)
class Port:
    number: int
    protocol: str
    state: str
    service: str | None = None


@dataclass
class Device:
    ip: str
    mac: str | None = None
    vendor: str | None = None
    hostname: str | None = None
    ports: list[Port] = field(default_factory=list)


def parse_nmap_xml(xml_text: str, include_down: bool = False) -> list[Device]:
    """Return devices from nmap XML. Hosts not ``up`` are skipped by default."""
    if not xml_text or not xml_text.strip():
        raise ParseError("nmap produced no output.", "Re-run the scan; check nmap is installed.")
    if "<!ENTITY" in xml_text:
        raise ParseError("nmap output contains unexpected XML entities; refusing to parse.")
    try:
        root = ET.fromstring(xml_text)  # noqa: S314 - entity declarations rejected above
    except ET.ParseError as exc:
        raise ParseError(
            "nmap output was incomplete or corrupted.",
            "The scan may have been interrupted; try running it again.",
        ) from exc
    if root.tag != "nmaprun":
        raise ParseError("This does not look like nmap XML output.")

    devices: list[Device] = []
    for host in root.findall("host"):
        status = host.find("status")
        if not include_down and status is not None and status.get("state") != "up":
            continue
        ip = mac = vendor = None
        for addr in host.findall("address"):
            kind = addr.get("addrtype")
            if kind == "ipv4" or (kind == "ipv6" and ip is None):
                ip = addr.get("addr")
            elif kind == "mac":
                mac = addr.get("addr")
                vendor = addr.get("vendor") or None
        if not ip:
            continue
        hn = host.find("hostnames/hostname")
        hostname = hn.get("name") if hn is not None else None
        ports = []
        for p in host.findall("ports/port"):
            st = p.find("state")
            svc = p.find("service")
            try:
                number = int(p.get("portid", ""))
            except ValueError:
                continue
            ports.append(
                Port(
                    number=number,
                    protocol=p.get("protocol", "tcp"),
                    state=st.get("state", "unknown") if st is not None else "unknown",
                    service=svc.get("name") if svc is not None else None,
                )
            )
        devices.append(Device(ip=ip, mac=mac, vendor=vendor, hostname=hostname, ports=ports))
    return devices

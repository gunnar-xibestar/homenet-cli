"""Parse nmap ``-oX`` XML into :class:`Device` objects. Never prints."""

from __future__ import annotations

from dataclasses import dataclass, field
from xml.etree.ElementTree import ParseError as XMLParseError  # noqa: S405 - type only

from defusedxml import DefusedXmlException
from defusedxml.ElementTree import fromstring

from homenet.core._text import DEFAULT_MAX_LEN, clean_text


def _clean(value: object) -> str | None:
    """Shared sanitiser, capped for core data (titles, headers, banners)."""
    return clean_text(value, DEFAULT_MAX_LEN)


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
    product: str | None = None  # from -sV, e.g. "OpenSSH"
    version: str | None = None  # from -sV, e.g. "9.2p1"


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
    try:
        root = fromstring(xml_text)
    except DefusedXmlException as exc:
        raise ParseError(
            "nmap output contains unsafe XML (entities/external references); refusing to parse."
        ) from exc
    except XMLParseError as exc:
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
                    service=_clean(svc.get("name")) if svc is not None else None,
                    product=_clean(svc.get("product")) if svc is not None else None,
                    version=_clean(svc.get("version")) if svc is not None else None,
                )
            )
        devices.append(Device(ip=ip, mac=mac, vendor=vendor, hostname=hostname, ports=ports))
    return devices

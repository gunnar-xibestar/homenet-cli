import pytest

from homenet.core.parser import Device, ParseError, Port, parse_nmap_xml


def test_hosts_fixture(load_fixture):
    devices = parse_nmap_xml(load_fixture("nmap_sn_hosts.xml"))
    assert [d.ip for d in devices] == [
        "192.168.1.1",
        "192.168.1.23",
        "192.168.1.42",
        "192.168.1.77",
        "192.168.1.100",
    ]
    assert devices[0] == Device(
        "192.168.1.1", "A4:2B:B0:11:22:33", "TP-Link Technologies", "router.lan", []
    )


def test_missing_vendor_mac_hostname(load_fixture):
    devices = {d.ip: d for d in parse_nmap_xml(load_fixture("nmap_sn_hosts.xml"))}
    assert devices["192.168.1.77"].mac == "7C:2F:80:DE:AD:01"
    assert devices["192.168.1.77"].vendor is None
    assert devices["192.168.1.42"].hostname is None
    me = devices["192.168.1.100"]
    assert me.mac is None and me.vendor is None and me.hostname == "gunnar-laptop"


def test_no_hosts(load_fixture):
    assert parse_nmap_xml(load_fixture("nmap_sn_no_hosts.xml")) == []


def test_truncated(load_fixture):
    with pytest.raises(ParseError, match="incomplete"):
        parse_nmap_xml(load_fixture("nmap_sn_truncated.xml"))


def test_ports_and_down_hosts(load_fixture):
    devices = parse_nmap_xml(load_fixture("nmap_ports.xml"))
    assert len(devices) == 1
    assert devices[0].ports == [
        Port(53, "tcp", "open", "domain"),
        Port(80, "tcp", "open", "http"),
        Port(443, "tcp", "filtered", None),
    ]
    assert len(parse_nmap_xml(load_fixture("nmap_ports.xml"), include_down=True)) == 2


@pytest.mark.parametrize("text", ["", "   ", "<html></html>", "not xml"])
def test_bad_input(text):
    with pytest.raises(ParseError):
        parse_nmap_xml(text)


@pytest.mark.parametrize(
    "entity",
    ['<!ENTITY a "b">', '<!ENTITY e SYSTEM "file:///etc/passwd">'],
    ids=["internal", "external"],
)
def test_entities_rejected(entity):
    xml = f'<?xml version="1.0"?><!DOCTYPE x [{entity}]><nmaprun>&a;&e;</nmaprun>'
    with pytest.raises(ParseError, match="unsafe"):
        parse_nmap_xml(xml)


def test_non_numeric_portid_skipped():
    xml = (
        '<nmaprun><host><status state="up"/><address addr="192.168.1.9" addrtype="ipv4"/>'
        '<ports><port protocol="tcp" portid="http"><state state="open"/></port>'
        '<port protocol="tcp" portid=""><state state="open"/></port>'
        '<port protocol="tcp" portid="22"><state state="open"/></port></ports></host></nmaprun>'
    )
    (dev,) = parse_nmap_xml(xml)
    assert dev.ports == [Port(22, "tcp", "open", None)]

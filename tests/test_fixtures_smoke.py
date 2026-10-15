"""Smoke tests: fixtures parse as expected and the subprocess guard works."""

import ipaddress
import re
import subprocess
import xml.etree.ElementTree as ET

import pytest


def test_nmap_hosts_xml_parses(load_fixture):
    root = ET.fromstring(load_fixture("nmap_sn_hosts.xml"))
    hosts = root.findall("host")
    assert len(hosts) == 5
    ips = [h.find("address[@addrtype='ipv4']").get("addr") for h in hosts]
    assert all(ipaddress.ip_address(ip).is_private for ip in ips)
    vendors = [
        m.get("vendor") for h in hosts if (m := h.find("address[@addrtype='mac']")) is not None
    ]
    assert "Raspberry Pi Foundation" in vendors
    assert None in vendors  # MAC with unknown vendor
    assert root.find("runstats/hosts").get("up") == "5"


def test_nmap_no_hosts_xml(load_fixture):
    root = ET.fromstring(load_fixture("nmap_sn_no_hosts.xml"))
    assert root.findall("host") == []
    assert root.find("runstats/hosts").get("up") == "0"


def test_nmap_truncated_xml_fails(load_fixture):
    with pytest.raises(ET.ParseError):
        ET.fromstring(load_fixture("nmap_sn_truncated.xml"))


def test_ip_json_fixtures(load_json_fixture):
    addrs = load_json_fixture("ip_addr.json")
    wlan = next(i for i in addrs if i["ifname"] == "wlp2s0")
    inet = next(a for a in wlan["addr_info"] if a["family"] == "inet")
    net = ipaddress.ip_interface(f"{inet['local']}/{inet['prefixlen']}").network
    assert str(net) == "192.168.1.0/24"
    routes = load_json_fixture("ip_route.json")
    assert next(r for r in routes if r["dst"] == "default")["gateway"] == "192.168.1.1"


def test_ip_route_text(load_fixture):
    first = load_fixture("ip_route.txt").splitlines()[0]
    assert re.match(r"default via (\S+) dev (\S+)", first).groups() == ("192.168.1.1", "wlp2s0")


@pytest.mark.parametrize(("name", "loss"), [("ping_success.txt", 0), ("ping_loss.txt", 100)])
def test_ping_loss(load_fixture, name, loss):
    m = re.search(r"(\d+)% packet loss", load_fixture(name))
    assert int(m.group(1)) == loss


def test_guard_blocks_real_commands():
    with pytest.raises(AssertionError, match="real command"):
        subprocess.run(["nmap", "-sn", "192.168.1.0/24"])  # noqa: S603, S607

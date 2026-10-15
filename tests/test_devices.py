import socket

import pytest

from homenet.core.devices import (
    find_device,
    get_device,
    mdns_name,
    normalize_mac,
    resolve_name,
    reverse_dns,
    sweep,
)
from homenet.core.parser import Device
from homenet.core.runner import NmapNotFoundError, ScanResult

NET = "192.168.1.0/24"


def fake_scan(load_fixture, calls=None):
    def scan(target, mode, **kw):
        if calls is not None:
            calls.append((target, mode, kw))
        return ScanResult(("nmap",), load_fixture("nmap_sn_hosts.xml"), "", 0)

    return scan


def test_sweep_uses_ping_mode_and_local_network(load_fixture):
    calls = []
    devices = sweep(NET, timeout=7, scan=fake_scan(load_fixture, calls), resolve_names=False)
    assert calls == [(NET, "ping", {"local_network": NET, "timeout": 7})]
    assert len(devices) == 5


def test_sweep_resolves_only_missing_names(load_fixture):
    asked = []

    def resolver(ip):
        asked.append(ip)
        return "tv.local" if ip == "192.168.1.42" else None

    devices = {d.ip: d for d in sweep(NET, scan=fake_scan(load_fixture), resolver=resolver)}
    assert asked == ["192.168.1.42", "192.168.1.77"]
    assert devices["192.168.1.42"].hostname == "tv.local"
    assert devices["192.168.1.77"].hostname is None
    assert devices["192.168.1.1"].hostname == "router.lan"


def test_sweep_propagates_runner_errors():
    def scan(*a, **k):
        raise NmapNotFoundError("nmap is not installed.")

    with pytest.raises(NmapNotFoundError):
        sweep(NET, scan=scan)


def test_reverse_dns():
    assert reverse_dns("192.168.1.1", lookup=lambda ip: ("router.lan", [], [ip])) == "router.lan"

    def fail(ip):
        raise socket.herror(1, "Unknown host")

    assert reverse_dns("192.168.1.9", lookup=fail) is None


def test_mdns_with_avahi(load_fixture):
    calls = []

    def run(args):
        calls.append(args)
        return load_fixture("avahi_resolve_a.txt")

    name = mdns_name("192.168.1.42", which=lambda n: "/usr/bin/avahi-resolve", run=run)
    assert name == "gunnars-macbook.local"
    assert calls == [["/usr/bin/avahi-resolve", "-a", "192.168.1.42"]]


def test_mdns_degrades_gracefully():
    assert mdns_name("192.168.1.42", which=lambda n: None) is None

    def boom(args):
        raise OSError("no daemon")

    assert mdns_name("192.168.1.42", which=lambda n: "/x", run=boom) is None
    assert mdns_name("192.168.1.42", which=lambda n: "/x", run=lambda a: "") is None
    assert mdns_name("not-an-ip; rm", which=lambda n: "/x", run=boom) is None


def test_resolve_name_order():
    assert resolve_name("1", reverse=lambda ip: "a", mdns=lambda ip: "b") == "a"
    assert resolve_name("1", reverse=lambda ip: None, mdns=lambda ip: "b") == "b"
    assert resolve_name("1", reverse=lambda ip: None, mdns=lambda ip: None) is None


@pytest.mark.parametrize(
    ("raw", "norm"),
    [
        ("A4:2B:B0:11:22:33", "a4:2b:b0:11:22:33"),
        ("a4-2b-b0-11-22-33", "a4:2b:b0:11:22:33"),
        (None, None),
        ("", None),
    ],
)
def test_normalize_mac(raw, norm):
    assert normalize_mac(raw) == norm


def test_find_device():
    devs = [Device("192.168.1.1", "A4:2B:B0:11:22:33"), Device("192.168.1.2")]
    assert find_device(devs, mac="a4-2b-b0-11-22-33").ip == "192.168.1.1"
    assert find_device(devs, ip="192.168.1.2").ip == "192.168.1.2"
    assert find_device(devs, ip="192.168.1.9") is None
    with pytest.raises(ValueError):
        find_device(devs)


def test_get_device(load_fixture):
    d = get_device(NET, mac="b8:27:eb:aa:bb:cc", scan=fake_scan(load_fixture), resolve_names=False)
    assert d.ip == "192.168.1.23"
    assert (
        get_device(NET, ip="192.168.1.250", scan=fake_scan(load_fixture), resolve_names=False)
        is None
    )
    with pytest.raises(ValueError):
        get_device(NET)

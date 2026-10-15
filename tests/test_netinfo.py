import subprocess

import pytest

from homenet.core.netinfo import (
    NetInfo,
    NetInfoError,
    detect,
    parse_default_route,
    parse_interface_addr,
    parse_proc_route,
)


def fake_ip(load_fixture):
    def run(args):
        if args[:2] == ["-j", "route"]:
            return load_fixture("ip_route.json")
        if args[:2] == ["-j", "addr"]:
            return load_fixture("ip_addr.json")
        raise AssertionError(args)

    return run


def test_detect_with_ip(load_fixture):
    assert detect(run=fake_ip(load_fixture)) == NetInfo(
        "wlp2s0", "192.168.1.100", "192.168.1.1", "192.168.1.0/24"
    )


def test_detect_falls_back_to_proc(load_fixture):
    def run(args):
        raise FileNotFoundError("ip")

    info = detect(run=run, read_file=lambda p: load_fixture("proc_net_route.txt"))
    assert info == NetInfo("wlp2s0", None, "192.168.1.1", None)


def test_detect_no_route():
    with pytest.raises(NetInfoError, match="No default route"):
        detect(run=lambda a: "[]")


def test_detect_nothing_available():
    def run(args):
        raise subprocess.SubprocessError

    def read(path):
        raise OSError

    with pytest.raises(NetInfoError) as ei:
        detect(run=run, read_file=read)
    assert "iproute2" in ei.value.hint


def test_lowest_metric_default_wins():
    routes = [
        {"dst": "default", "gateway": "10.0.0.1", "dev": "eth0", "metric": 100},
        {"dst": "default", "gateway": "192.168.1.1", "dev": "wlp2s0", "metric": 600},
    ]
    assert parse_default_route(routes) == ("eth0", "10.0.0.1")


def test_interface_without_ipv4(load_json_fixture):
    assert parse_interface_addr(load_json_fixture("ip_addr.json"), "nope") == (None, None)
    assert parse_interface_addr(load_json_fixture("ip_addr.json"), "docker0") == (
        "172.17.0.1",
        "172.17.0.0/16",
    )


def test_proc_route_no_default():
    with pytest.raises(NetInfoError):
        parse_proc_route("Iface\tDestination\n" + "eth0\t0001A8C0\t00000000\t1\t0\t0\t0\t0\n")


def test_bad_json_falls_back(load_fixture):
    info = detect(run=lambda a: "{not json", read_file=lambda p: load_fixture("proc_net_route.txt"))
    assert info.interface == "wlp2s0"

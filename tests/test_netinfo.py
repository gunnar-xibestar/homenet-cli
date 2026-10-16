import ipaddress
import json
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
    def unread(path):
        raise OSError(path)

    assert detect(run=fake_ip(load_fixture), read_file=unread) == NetInfo(
        "wlp2s0", "192.168.1.100", "192.168.1.1", "192.168.1.0/24"
    )


def test_detect_mac_falls_back_to_none(load_fixture):
    mac_path = "/sys/class/net/wlp2s0/address"

    def read_ok(path):
        if path == mac_path:
            return "B8:27:EB:AA:BB:CC\n"
        raise OSError(path)

    info = detect(run=fake_ip(load_fixture), read_file=read_ok)
    assert info.mac == "b8:27:eb:aa:bb:cc"
    assert info.ip == "192.168.1.100" and info.interface == "wlp2s0"

    def read_fail(path):
        raise OSError(path)

    failed = detect(run=fake_ip(load_fixture), read_file=read_fail)
    assert failed.mac is None
    assert failed.ip == "192.168.1.100" and failed.interface == "wlp2s0"


@pytest.mark.parametrize(
    ("env", "version", "flag"),
    [
        ({"WSL_DISTRO_NAME": "Ubuntu"}, None, True),
        ({}, "Linux version 6.12.94+", False),
    ],
    ids=["wsl", "not-wsl"],
)
def test_detect_sets_wsl_nat(env, version, flag):
    local, prefix = "172.22.240.5", 20
    network = ipaddress.ip_network(f"{local}/{prefix}", strict=False)
    gateway = str(next(network.hosts()))

    def run(args):
        if args[1] == "route":
            body = [{"dst": "default", "gateway": gateway, "dev": "eth0", "metric": 0}]
        elif args[1] == "addr":
            body = [
                {
                    "ifname": "eth0",
                    "addr_info": [{"family": "inet", "local": local, "prefixlen": prefix}],
                }
            ]
        else:
            raise AssertionError(args)
        return json.dumps(body)

    def read(path):
        if path == "/proc/version" and version is not None:
            return version
        raise OSError(path)

    info = detect(run=run, read_file=read, environ=env)
    assert info.wsl_nat is flag
    assert info.ip == local
    assert info.subnet == str(network)
    assert info.interface == "eth0"


def test_detect_falls_back_to_proc(load_fixture):
    def run(args):
        raise FileNotFoundError("ip")

    info = detect(run=run, read_file=lambda p: load_fixture("proc_net_route.txt"))
    assert info == NetInfo("wlp2s0", None, "192.168.1.1", "192.168.1.0/24")


def test_detect_no_route():
    with pytest.raises(NetInfoError, match="No default route"):
        detect(run=lambda a: "[]", read_file=_no_files)


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


def test_proc_route_subnet(load_fixture):
    assert parse_proc_route(load_fixture("proc_net_route.txt")) == (
        "wlp2s0",
        "192.168.1.1",
        "192.168.1.0/24",
    )


def test_proc_route_garbage_lines_ignored(load_fixture):
    text = load_fixture("proc_net_route.txt") + "junk zz yy 1 2 3 x 4\nshort\n"
    assert parse_proc_route(text)[0] == "wlp2s0"


def test_null_or_missing_metric():
    routes = [
        {"dst": "default", "gateway": "192.168.1.1", "dev": "wlp2s0", "metric": None},
        {"dst": "default", "gateway": "10.0.0.1", "dev": "eth0", "metric": 100},
        {"dst": "default", "dev": "tun0"},
    ]
    assert parse_default_route(routes)[0] in {"wlp2s0", "tun0"}


@pytest.mark.parametrize(
    "routes",
    [
        None,
        {},
        {"dst": "default"},
        "default",
        [None, 1, "x"],
        [{"dst": "default"}],
        [{"dst": "default", "dev": None}],
        [{"dev": "eth0"}],
    ],
)
def test_malformed_routes_raise_netinfoerror(routes):
    with pytest.raises(NetInfoError):
        parse_default_route(routes)


@pytest.mark.parametrize(
    "addrs",
    [
        [],
        [None],
        [{"ifname": "wlp2s0"}],
        [{"ifname": "wlp2s0", "addr_info": None}],
        [
            {
                "ifname": "wlp2s0",
                "addr_info": [
                    {"family": "inet"},
                    None,
                    {"family": "inet", "local": "x", "prefixlen": 24},
                ],
            }
        ],
    ],
)
def test_malformed_addrs(addrs):
    assert parse_interface_addr(addrs, "wlp2s0") == (None, None)


def test_addrs_not_a_list():
    with pytest.raises(NetInfoError):
        parse_interface_addr({"ifname": "wlp2s0"}, "wlp2s0")


@pytest.mark.parametrize("route_json", ["null", "{}", '"x"', '[{"dst": "default"}]'])
def test_detect_malformed_ip_json(route_json):
    with pytest.raises(NetInfoError):
        detect(run=lambda a: route_json, read_file=_no_files)


def _no_files(path):
    raise AssertionError(f"unexpected file read: {path}")

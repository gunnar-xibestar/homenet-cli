import subprocess
from types import SimpleNamespace

import pytest

from homenet.core import runner
from homenet.core.runner import (
    DisallowedFlagError,
    InvalidTargetError,
    NmapFailedError,
    NmapNotFoundError,
    NmapPermissionError,
    NmapTimeoutError,
    TargetNotAllowedError,
    build_args,
    check_flags,
    default_route_network,
    run_scan,
    validate_target,
)

LOCAL = "192.168.1.0/24"
ROOT = {"geteuid": lambda: 0}
USER = {"geteuid": lambda: 1000, "read_text": lambda p: "CapEff:\t0000000000000000\n"}


def test_default_is_ping_scan():
    assert build_args("192.168.1.0/24", local_network=LOCAL) == [
        "nmap",
        "-sn",
        "-T4",
        "-oX",
        "-",
        "192.168.1.0/24",
    ]


@pytest.mark.parametrize(("mode", "flag"), [("tcp-connect", "-sT"), ("syn", "-sS")])
def test_port_modes_use_top_ports(mode, flag):
    args = build_args("192.168.1.5", mode, 20, local_network=LOCAL)
    assert args[1:4] == [flag, "--top-ports", "20"]
    assert args[-1] == "192.168.1.5/32"


@pytest.mark.parametrize(
    ("mode", "top"),
    [("syn", 0), ("syn", 1001), ("syn", True), ("syn", "10"), ("aggressive", 100)],
    ids=["top-0", "top-over-cap", "top-bool", "top-str", "unknown-mode"],
)
def test_build_args_rejects_bad_mode_or_top_ports(mode, top):
    with pytest.raises(DisallowedFlagError):
        build_args("192.168.1.5", mode, top, local_network=LOCAL)


@pytest.mark.parametrize(
    "flag",
    ["-sV", "-A", "-O", "--script", "--script=vuln", "-sC", "-sU", "-p-", "-p1-65535", "--evil"],
)
def test_blocked_flags(flag):
    with pytest.raises(DisallowedFlagError):
        check_flags([flag])


@pytest.mark.parametrize(
    "t",
    [
        "",
        "  ",
        "-sV",
        "192.168.1.1; rm -rf /",
        "192.168.1.1 192.168.1.2",
        "foo",
        "300.1.1.1",
        "fe80::1",
    ],
)
def test_invalid_targets(t):
    with pytest.raises(InvalidTargetError):
        validate_target(t, LOCAL)


@pytest.mark.parametrize("t", ["8.8.8.8", "1.0.0.0/24", "10.0.0.0/8", "172.16.0.0/12"])
def test_public_or_huge_refused_even_with_force(t):
    with pytest.raises(TargetNotAllowedError):
        validate_target(t, force=True)


@pytest.mark.parametrize("local", [LOCAL, None], ids=["other-subnet", "no-local-network"])
def test_outside_local_subnet_needs_force(local):
    with pytest.raises(TargetNotAllowedError, match="outside your local subnet"):
        validate_target("10.0.5.0/24", local)
    assert str(validate_target("10.0.5.0/24", local, force=True)) == "10.0.5.0/24"


def _fake_run(monkeypatch, result=None, exc=None):
    calls = []

    def fake(args, **kw):
        calls.append((args, kw))
        if exc:
            raise exc
        return result

    monkeypatch.setattr(runner.shutil, "which", lambda name: "/usr/bin/nmap")
    monkeypatch.setattr(runner.subprocess, "run", fake)
    return calls


def test_run_scan_success(monkeypatch, load_fixture):
    xml = load_fixture("nmap_sn_hosts.xml")
    calls = _fake_run(monkeypatch, SimpleNamespace(returncode=0, stdout=xml, stderr=""))
    res = run_scan("192.168.1.0/24", local_network=LOCAL, timeout=5)
    assert res.xml == xml
    args, kw = calls[0]
    assert isinstance(args, list) and args[0] == "/usr/bin/nmap"
    assert kw["shell"] is False and kw["timeout"] == 5


def test_run_scan_missing_nmap_is_silent(monkeypatch, capsys):
    monkeypatch.setattr(runner.shutil, "which", lambda name: None)
    with pytest.raises(NmapNotFoundError) as ei:
        run_scan("192.168.1.0/24", local_network=LOCAL)
    assert "apt install nmap" in ei.value.hint
    assert capsys.readouterr() == ("", "")  # core never prints


@pytest.mark.parametrize(
    ("result", "exc", "error"),
    [
        (None, subprocess.TimeoutExpired("nmap", 1), NmapTimeoutError),
        (SimpleNamespace(returncode=2, stdout="", stderr="boom"), None, NmapFailedError),
        # Root is detected up front, never by matching nmap's stderr text.
        (
            SimpleNamespace(returncode=1, stdout="", stderr="requires root privileges"),
            None,
            NmapFailedError,
        ),
    ],
    ids=["timeout", "nonzero-exit", "root-text-not-matched"],
)
def test_run_scan_failures(monkeypatch, result, exc, error):
    _fake_run(monkeypatch, result, exc)
    with pytest.raises(error) as ei:
        run_scan("192.168.1.0/24", local_network=LOCAL, timeout=1)
    if result is not None:
        assert ei.value.returncode == result.returncode
        assert ei.value.stderr == result.stderr


def test_syn_needs_root_detected_up_front(monkeypatch):
    calls = _fake_run(monkeypatch, None)
    with pytest.raises(NmapPermissionError) as ei:
        run_scan("192.168.1.0/24", "syn", local_network=LOCAL, **USER)
    assert "sudo" in ei.value.hint
    assert calls == []  # nmap never started


@pytest.mark.parametrize(
    ("privs", "privileged_flag"),
    [(ROOT, False), ({"geteuid": lambda: 1000, "read_text": lambda p: "CapEff:\t2000\n"}, True)],
    ids=["root", "cap-net-raw"],
)
def test_syn_with_privileges(monkeypatch, privs, privileged_flag):
    calls = _fake_run(monkeypatch, SimpleNamespace(returncode=0, stdout="<x/>", stderr=""))
    run_scan("192.168.1.0/24", "syn", local_network=LOCAL, **privs)
    assert ("--privileged" in calls[0][0]) is privileged_flag


def test_default_route_network_ignores_bridges(load_json_fixture):
    net = default_route_network(
        load_json_fixture("ip_route.json"), load_json_fixture("ip_addr.json")
    )
    assert str(net) == "192.168.1.0/24"
    with pytest.raises(TargetNotAllowedError):
        validate_target("172.17.0.0/24", net)  # docker0 subnet is not local


@pytest.mark.parametrize(
    ("routes", "addrs"),
    [
        (None, []),
        ([], []),
        ([{"dst": "default"}], []),
        ({"dst": "default"}, {}),
        (
            [{"dst": "default", "dev": "eth0", "metric": None}],
            [{"ifname": "eth0", "addr_info": None}],
        ),
    ],
)
def test_default_route_network_malformed(routes, addrs):
    assert default_route_network(routes, addrs) is None


def test_validation_happens_before_running(monkeypatch):
    calls = _fake_run(monkeypatch, None)
    with pytest.raises(TargetNotAllowedError):
        run_scan("8.8.8.8", local_network=LOCAL)
    assert calls == []

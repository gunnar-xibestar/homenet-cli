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
    run_scan,
    validate_target,
)

LOCAL = ["192.168.1.0/24"]


def test_default_is_ping_scan():
    assert build_args("192.168.1.0/24", local_networks=LOCAL) == [
        "nmap",
        "-sn",
        "-T4",
        "-oX",
        "-",
        "192.168.1.0/24",
    ]


@pytest.mark.parametrize(("mode", "flag"), [("tcp-connect", "-sT"), ("syn", "-sS")])
def test_port_modes_use_top_ports(mode, flag):
    args = build_args("192.168.1.5", mode, 20, local_networks=LOCAL)
    assert args[1:4] == [flag, "--top-ports", "20"]
    assert args[-1] == "192.168.1.5/32"


@pytest.mark.parametrize("n", [0, 1001, True, "10"])
def test_bad_top_ports(n):
    with pytest.raises(DisallowedFlagError):
        build_args("192.168.1.5", "syn", n, local_networks=LOCAL)


def test_unknown_mode():
    with pytest.raises(DisallowedFlagError):
        build_args("192.168.1.0/24", "aggressive", local_networks=LOCAL)


@pytest.mark.parametrize(
    "flag",
    ["-sV", "-A", "-O", "--script", "--script=vuln", "-sC", "-sU", "-p-", "-p1-65535", "--evil"],
)
def test_blocked_flags(flag):
    with pytest.raises(DisallowedFlagError):
        check_flags([flag])


@pytest.mark.parametrize(
    "t", ["", "  ", "-sV", "192.168.1.1; rm -rf /", "foo", "300.1.1.1", "fe80::1"]
)
def test_invalid_targets(t):
    with pytest.raises(InvalidTargetError):
        validate_target(t, LOCAL)


@pytest.mark.parametrize("t", ["8.8.8.8", "1.0.0.0/24", "10.0.0.0/8", "172.16.0.0/12"])
def test_public_or_huge_refused_even_with_force(t):
    with pytest.raises(TargetNotAllowedError):
        validate_target(t, force=True)


def test_outside_local_subnet_needs_force():
    with pytest.raises(TargetNotAllowedError, match="outside your local subnet"):
        validate_target("10.0.5.0/24", LOCAL)
    assert str(validate_target("10.0.5.0/24", LOCAL, force=True)) == "10.0.5.0/24"


def test_no_local_networks_refused():
    with pytest.raises(TargetNotAllowedError):
        validate_target("192.168.1.0/24")


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
    res = run_scan("192.168.1.0/24", local_networks=LOCAL, timeout=5)
    assert res.xml == xml
    args, kw = calls[0]
    assert isinstance(args, list) and args[0] == "/usr/bin/nmap"
    assert kw["shell"] is False and kw["timeout"] == 5


def test_run_scan_missing_nmap(monkeypatch):
    monkeypatch.setattr(runner.shutil, "which", lambda name: None)
    with pytest.raises(NmapNotFoundError) as ei:
        run_scan("192.168.1.0/24", local_networks=LOCAL)
    assert "apt install nmap" in ei.value.hint


def test_run_scan_timeout(monkeypatch):
    _fake_run(monkeypatch, exc=subprocess.TimeoutExpired("nmap", 1))
    with pytest.raises(NmapTimeoutError):
        run_scan("192.168.1.0/24", local_networks=LOCAL, timeout=1)


def test_run_scan_needs_root(monkeypatch):
    _fake_run(
        monkeypatch,
        SimpleNamespace(
            returncode=1,
            stdout="",
            stderr="You requested a scan type which requires root privileges.",
        ),
    )
    with pytest.raises(NmapPermissionError):
        run_scan("192.168.1.0/24", "syn", local_networks=LOCAL)


def test_run_scan_failure(monkeypatch):
    _fake_run(monkeypatch, SimpleNamespace(returncode=2, stdout="", stderr="boom"))
    with pytest.raises(NmapFailedError) as ei:
        run_scan("192.168.1.0/24", local_networks=LOCAL)
    assert ei.value.returncode == 2 and ei.value.stderr == "boom"


def test_validation_happens_before_running(monkeypatch):
    calls = _fake_run(monkeypatch, None)
    with pytest.raises(TargetNotAllowedError):
        run_scan("8.8.8.8", local_networks=LOCAL)
    assert calls == []


def test_runner_never_prints(monkeypatch, capsys):
    monkeypatch.setattr(runner.shutil, "which", lambda name: None)
    with pytest.raises(NmapNotFoundError):
        run_scan("192.168.1.0/24", local_networks=LOCAL)
    assert capsys.readouterr() == ("", "")

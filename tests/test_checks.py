import dataclasses
import re

import pytest

from homenet.cli import build_parser
from homenet.core.checks import (
    CheckResult,
    check_network,
    check_ping,
    check_privileges,
    check_tool,
    run_all_checks,
)

ROUTE = (
    "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"
    "wlp2s0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\n"
)


def test_checkresult_contract():
    fields = [(f.name, f.type, f.default) for f in dataclasses.fields(CheckResult)]
    assert [f[0] for f in fields] == ["name", "ok", "detail", "fix_hint", "severity"]
    r = CheckResult("x", True, "d")
    assert r.fix_hint is None and r.severity == "error"


@pytest.mark.parametrize(
    ("tool", "out", "version"),
    [
        ("nmap", "Nmap version 7.94SVN ( https://nmap.org )\n", "7.94SVN"),
        ("ip", "ip utility, iproute2-6.1.0", "6.1.0"),
    ],
)
def test_tool_found_reads_version(tool, out, version):
    r = check_tool(tool, which=lambda n: f"/usr/bin/{n}", run=lambda a: out)
    assert r.ok and version in r.detail and r.fix_hint is None


def test_tool_missing_has_apt_hint():
    r = check_tool("nmap", which=lambda n: None)
    assert not r.ok and r.fix_hint == "sudo apt install nmap"
    assert check_tool("ip", which=lambda n: None).fix_hint == "sudo apt install iproute2"


def test_tool_version_error_still_ok():
    def boom(a):
        raise OSError("nope")

    assert check_tool("nmap", which=lambda n: "/usr/bin/nmap", run=boom).ok


def test_privileges_root_and_sudo():
    assert check_privileges(geteuid=lambda: 0, environ={}).ok
    r = check_privileges(geteuid=lambda: 0, environ={"SUDO_USER": "gunnar"})
    assert r.ok and "sudo" in r.detail


def test_privileges_cap_net_raw():
    status = "Name:\tpython\nCapEff:\t0000000000002000\n"
    assert check_privileges(geteuid=lambda: 1000, read_text=lambda p: status, environ={}).ok


def test_privileges_unprivileged_is_warning():
    r = check_privileges(geteuid=lambda: 1000, read_text=lambda p: "CapEff:\t0\n", environ={})
    assert not r.ok and r.severity == "warning"
    assert r.fix_hint == "Re-run with sudo, for example `sudo homenet devices`."
    assert "setcap" not in r.fix_hint
    named = re.search(r"`sudo homenet ([a-z0-9-]+)`", r.fix_hint or "")
    assert named is not None
    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args([named.group(1), "--help"])
    assert exc.value.code == 0


def test_network_ok():
    files = {"/proc/net/route": ROUTE, "/sys/class/net/wlp2s0/operstate": "up\n"}
    r = check_network(read_text=files.__getitem__)
    assert r.ok and "wlp2s0" in r.detail


def test_network_no_route():
    r = check_network(read_text=lambda p: "Iface\tDestination\n")
    assert not r.ok and r.fix_hint


def test_network_interface_down():
    files = {"/proc/net/route": ROUTE, "/sys/class/net/wlp2s0/operstate": "down\n"}
    assert not check_network(read_text=files.__getitem__).ok


def _files(load_fixture, operstate="up\n"):
    files = {
        "/proc/net/route": ROUTE,
        "/sys/class/net/wlp2s0/operstate": operstate,
        "/proc/self/status": "CapEff:\t0000000000000000\n",
    }

    def read(path):
        if path not in files:
            raise AssertionError(f"unexpected real file read: {path}")
        return files[path]

    return read


def _runner(load_fixture, ping="ping_success.txt"):
    def run(args):
        name = args[0].rsplit("/", 1)[-1]
        if name == "ping":
            return load_fixture(ping)
        return {"nmap": "Nmap version 7.94\n", "ip": "ip utility, iproute2-6.1.0"}[name]

    return run


@pytest.mark.parametrize(
    ("fixture", "ok", "severity"),
    [("ping_success.txt", True, "ok"), ("ping_loss.txt", False, "warning")],
)
def test_ping_gateway(load_fixture, fixture, ok, severity):
    calls = []

    def run(args):
        calls.append(args)
        return load_fixture(fixture)

    r = check_ping(which=lambda n: "/usr/bin/ping", run=run, read_text=_files(load_fixture))
    assert (r.ok, r.severity) == (ok, severity)
    assert calls == [["/usr/bin/ping", "-c", "3", "-W", "1", "-q", "192.168.1.1"]]


def test_ping_partial_loss():
    out = "3 packets transmitted, 2 received, 33.3333% packet loss, time 2003ms"
    r = check_ping("192.168.1.1", which=lambda n: "/bin/ping", run=lambda a: out)
    assert r.ok and r.severity == "warning" and "33.3333%" in r.detail


def test_ping_missing_and_bad_input():
    r = check_ping("192.168.1.1", which=lambda n: None)
    assert not r.ok and r.fix_hint == "sudo apt install iputils-ping"
    assert not check_ping("1.2.3.4; reboot", which=lambda n: "/bin/ping").ok
    assert not check_ping(read_text=lambda p: "Iface\tDestination\n").ok
    assert not check_ping("192.168.1.1", which=lambda n: "/bin/ping", run=lambda a: "??").ok


def test_run_all_checks_uses_only_fakes(load_fixture, capsys):
    results = run_all_checks(
        which=lambda n: f"/usr/bin/{n}",
        run=_runner(load_fixture),
        geteuid=lambda: 1000,
        read_text=_files(load_fixture),
        environ={},
    )
    assert [r.name for r in results] == ["nmap", "ip", "privileges", "network", "ping"]
    assert [r.severity for r in results] == ["ok", "ok", "warning", "ok", "ok"]
    assert capsys.readouterr() == ("", "")


def test_run_all_checks_nothing_installed(load_fixture):
    results = run_all_checks(
        which=lambda n: None, geteuid=lambda: 0, read_text=_files(load_fixture), environ={}
    )
    assert [r.ok for r in results] == [False, False, True, True, False]

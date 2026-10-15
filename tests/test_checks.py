import dataclasses

from homenet.core import checks
from homenet.core.checks import (
    CheckResult,
    check_network,
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
    assert [f[0] for f in fields] == ["name", "ok", "detail", "fix_hint"]
    assert CheckResult("x", True, "d").fix_hint is None


def test_tool_found_reads_version():
    r = check_tool(
        "nmap",
        which=lambda n: "/usr/bin/nmap",
        run=lambda a: "Nmap version 7.94SVN ( https://nmap.org )\n",
    )
    assert r.ok and "7.94SVN" in r.detail and r.fix_hint is None


def test_tool_ip_version():
    r = check_tool("ip", which=lambda n: "/usr/bin/ip", run=lambda a: "ip utility, iproute2-6.1.0")
    assert r.ok and "6.1.0" in r.detail


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


def test_privileges_unprivileged_hint():
    r = check_privileges(geteuid=lambda: 1000, read_text=lambda p: "CapEff:\t0\n", environ={})
    assert not r.ok and "sudo" in r.fix_hint and "setcap" in r.fix_hint


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


def test_run_all_checks(monkeypatch, capsys):
    monkeypatch.setattr(checks.shutil, "which", lambda n: None)
    monkeypatch.setattr(checks.os, "geteuid", lambda: 1000)
    results = run_all_checks()
    assert [r.name for r in results] == ["nmap", "ip", "privileges", "network"]
    assert all(isinstance(r, CheckResult) for r in results)
    assert capsys.readouterr() == ("", "")

"""Contract tests for the doctor check stubs. They never print or exit."""

from __future__ import annotations

from homenet.core import checks
from homenet.core.checks import (
    CheckResult,
    check_network,
    check_privileges,
    check_tool,
    run_all_checks,
)


def test_missing_tool_has_fix_hint_and_is_silent(monkeypatch, capsys):
    monkeypatch.setattr(checks.shutil, "which", lambda _name: None)
    result = check_tool("nmap")
    assert result == CheckResult(
        "nmap",
        False,
        "nmap is not installed (not found on PATH).",
        "sudo apt install nmap",
    )
    assert check_tool("ip").fix_hint == "sudo apt install iproute2"
    assert capsys.readouterr() == ("", "")


def test_tool_found_reports_version(monkeypatch, capsys):
    monkeypatch.setattr(checks.shutil, "which", lambda _name: "/usr/bin/nmap")

    class _Proc:
        stdout = "Nmap version 7.94SVN ( https://nmap.org )\n"
        stderr = ""

    monkeypatch.setattr(checks.subprocess, "run", lambda *_args, **_kwargs: _Proc())
    result = check_tool("nmap")
    assert result.ok is True
    assert result.fix_hint is None
    assert "7.94SVN" in result.detail
    assert capsys.readouterr() == ("", "")


def test_unprivileged_returns_hint_without_raising(monkeypatch, capsys):
    monkeypatch.setattr(checks.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(
        checks.Path,
        "read_text",
        lambda _self, *_args, **_kwargs: "CapEff:\t0000000000000000\n",
    )
    result = check_privileges()
    assert result.ok is False
    assert result.fix_hint is not None
    assert "sudo" in result.fix_hint
    assert "setcap" in result.fix_hint
    assert "cap_net_raw+ep" in result.fix_hint
    assert capsys.readouterr() == ("", "")


def test_root_and_cap_net_raw_pass(monkeypatch):
    monkeypatch.setattr(checks.os, "geteuid", lambda: 0)
    assert check_privileges().ok is True

    monkeypatch.setattr(checks.os, "geteuid", lambda: 1000)
    status = "Name:\tpython\nCapEff:\t0000000000002000\n"
    monkeypatch.setattr(checks.Path, "read_text", lambda _self, *_a, **_k: status)
    result = check_privileges()
    assert result.ok is True
    assert result.fix_hint is None


def test_network_reports_default_route_and_interface(monkeypatch, capsys):
    route = (
        "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"
        "wlp2s0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\n"
    )

    def read_text(self, *_args, **_kwargs):
        if str(self).endswith("operstate"):
            return "up\n"
        return route

    monkeypatch.setattr(checks.Path, "read_text", read_text)
    result = check_network()
    assert result.ok is True
    assert "192.168.1.1" in result.detail
    assert "wlp2s0" in result.detail
    assert "interface" in result.detail
    assert capsys.readouterr() == ("", "")


def test_network_missing_route_and_down_interface(monkeypatch):
    monkeypatch.setattr(
        checks.Path,
        "read_text",
        lambda _self, *_a, **_k: "Iface\tDestination\n",
    )
    missing = check_network()
    assert missing.ok is False
    assert missing.fix_hint

    route = (
        "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"
        "wlp2s0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\n"
    )

    def read_text(self, *_args, **_kwargs):
        if str(self).endswith("operstate"):
            return "down\n"
        return route

    monkeypatch.setattr(checks.Path, "read_text", read_text)
    down = check_network()
    assert down.ok is False
    assert "wlp2s0" in down.detail
    assert down.fix_hint


def test_run_all_checks_order_and_silence(monkeypatch, capsys):
    monkeypatch.setattr(checks.shutil, "which", lambda _name: None)
    monkeypatch.setattr(checks.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(checks.Path, "read_text", lambda _self, *_a, **_k: "CapEff:\t0\n")
    results = run_all_checks()
    assert [result.name for result in results] == ["nmap", "ip", "privileges", "network"]
    assert all(isinstance(result, CheckResult) for result in results)
    assert capsys.readouterr() == ("", "")

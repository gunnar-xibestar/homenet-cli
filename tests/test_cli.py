"""CLI commands, exit codes and JSON output. Core is mocked; nothing real runs."""

from __future__ import annotations

import json
import os
import sys
from importlib.metadata import PackageNotFoundError
from pathlib import Path

import pytest

from homenet import __version__, cli
from homenet.cli import BANNER, main
from homenet.core import (
    baseline,
    checks,
    devices,
    dns,
    netinfo,
    port_notes,
    ports,
    router,
    speed,
    wifi,
)
from homenet.core.baseline import BaselineError, BaselineNotFoundError, diff_devices
from homenet.core.checks import CheckResult
from homenet.core.dns import DnsConfig, DnsServer, LookupResult
from homenet.core.netinfo import NetInfo, NetInfoError
from homenet.core.parser import Device, ParseError, Port
from homenet.core.router import AdminPage, RouterCheck
from homenet.core.runner import NmapNotFoundError, TargetNotAllowedError
from homenet.core.speed import SpeedError, SpeedResult
from homenet.core.wifi import WifiInfo
from homenet.output import (
    format_device,
    format_device_json,
    format_devices,
    format_devices_json,
    format_diff,
    format_diff_json,
    format_dns_json,
    format_doctor_json,
    format_error,
    format_error_json,
    format_ports,
    format_ports_json,
    format_router,
    format_router_json,
    format_services,
    format_services_json,
    format_speed,
    format_speed_json,
    format_whoami,
    format_whoami_json,
    format_wifi,
    format_wifi_json,
)

# Wording from homenet.core.checks.privilege_fix_hint for a resolved program path.
PRIVILEGE_HINT = (
    "To see MAC addresses and makers, run `sudo /opt/venv/bin/homenet devices`. "
    "homenet doctor does not need sudo."
)


_SUBCOMMANDS = (
    "whoami-net",
    "devices",
    "device",
    "ports",
    "services",
    "router",
    "baseline",
    "new-devices",
    "speed",
    "wifi",
    "dns",
    "doctor",
    "explain",
)

# Root changes the ping sweep. ports, services, and router do not need it.
_SUDO_HELP = frozenset({"devices", "device", "baseline", "new-devices"})


@pytest.mark.parametrize("command", [None, *_SUBCOMMANDS])
def test_help_exits_zero(command, capsys):
    """Every --help exits 0 with output. Only the sudo heading is checked."""
    with pytest.raises(SystemExit) as exc:
        main([command, "--help"] if command else ["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert out.strip()
    heading = "Running with sudo (Debian/Ubuntu)"
    assert (heading in out) is (command is None or command in _SUDO_HELP)


@pytest.mark.parametrize("argv", [[], ["device"], ["ports"], ["services"]])
def test_usage_errors_exit_nonzero(argv):
    with pytest.raises(SystemExit) as exc:
        main(argv)
    assert exc.value.code == 2


@pytest.mark.parametrize("metadata", ["1.2.3", None])
def test_version_flag_uses_installed_metadata(metadata, monkeypatch, capsys):
    def fake(name: str) -> str:
        assert name == "homenet-cli"
        if metadata is None:
            raise PackageNotFoundError(name)
        return metadata

    monkeypatch.setattr("homenet.cli.distribution_version", fake)
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    expected = metadata if metadata is not None else __version__
    assert capsys.readouterr().out == f"homenet {expected}\n"


def test_cli_source_does_not_spawn_processes():
    root = Path(checks.__file__).resolve().parent.parent
    for name in ("cli.py", "output.py"):
        source = (root / name).read_text(encoding="utf-8")
        assert "subprocess" not in source
        assert "os.system" not in source
        assert "Popen" not in source


def _patch_detect(monkeypatch, result: NetInfo | NetInfoError) -> None:
    def detect() -> NetInfo:
        if isinstance(result, NetInfoError):
            raise result
        return result

    monkeypatch.setattr(netinfo, "detect", detect)


def test_whoami_json_includes_the_wsl_flag(capsys, monkeypatch):
    info = NetInfo("eth0", "172.22.240.5", "172.22.240.1", "172.22.240.0/20", wsl_nat=True)
    _patch_detect(monkeypatch, info)
    assert main(["whoami-net", "--json"]) == 0
    loaded = json.loads(capsys.readouterr().out)
    assert loaded["wsl_nat"] is True
    assert loaded["warning"]


def test_whoami_net_prints_core_netinfo(capsys, monkeypatch):
    info = NetInfo("wlp2s0", "192.168.1.100", "192.168.1.1", "192.168.1.0/24")
    _patch_detect(monkeypatch, info)
    assert main(["whoami-net"]) == 0
    captured = capsys.readouterr()
    assert captured.out == "·\n" * 2 + format_whoami(info) + "\n" + "·\n" * 5
    assert captured.err == ""
    assert "not implemented" not in captured.out


@pytest.mark.parametrize("hint", ["Connect to Wi-Fi or Ethernet and try again.", None])
def test_whoami_net_error_without_a_traceback(hint, capsys, monkeypatch):
    error = NetInfoError("No default route found; you may not be connected to a network.", hint)
    _patch_detect(monkeypatch, error)
    assert main(["whoami-net"]) == 1
    captured = capsys.readouterr()
    assert captured.out == format_error(str(error), hint) + "\n"
    assert ("Fix:" in captured.out) is (hint is not None)
    assert "Traceback" not in captured.out + captured.err
    assert "NetInfoError" not in captured.out


def _patch_checks(monkeypatch, results: list[CheckResult]) -> None:
    monkeypatch.setattr(checks, "run_all_checks", lambda: results)
    # These tests supply the check list. Optional Wi-Fi/DNS tools are covered
    # on their own, so they must not call the real version commands here.
    monkeypatch.setattr(checks, "OPTIONAL_TOOLS", ())


@pytest.mark.parametrize(
    ("results", "code", "present", "absent"),
    [
        (
            [CheckResult("nmap", True, "nmap 7.95"), CheckResult("ip", True, "ip 6.1.0")],
            0,
            ["PASS  nmap", "PASS  ip", "All 2 checks passed."],
            ["FAIL", BANNER],
        ),
        (
            [
                CheckResult("nmap", False, "not installed", "sudo apt install nmap"),
                CheckResult("ip", True, "ip 6.1.0"),
            ],
            1,
            ["FAIL  nmap", "PASS  ip", "Fix: sudo apt install nmap", "1 check failed."],
            [],
        ),
        (
            [CheckResult("privileges", False, "normal user", PRIVILEGE_HINT, "warning")],
            0,
            ["WARN  privileges", PRIVILEGE_HINT, "No errors. 1 warning."],
            ["FAIL", "setcap", "sudo homenet doctor"],
        ),
        (
            [
                CheckResult("nmap", False, "not installed", "sudo apt install nmap", "error"),
                CheckResult("privileges", False, "normal user", "Re-run with sudo", "warning"),
            ],
            1,
            ["FAIL  nmap", "WARN  privileges", "1 check failed. 1 warning."],
            [],
        ),
        (
            [CheckResult("network", False, "via eth0\x1b[2J", "Check wlan0\x1b]0;x\x07", "error")],
            1,
            ["via eth0?[2J", "Fix: Check wlan0?]0;x?"],
            ["\x1b", "\x07"],
        ),
    ],
    ids=["pass", "error", "warning-only", "error-and-warning", "cleans-network-text"],
)
def test_doctor_plain(results, code, present, absent, capsys, monkeypatch):
    _patch_checks(monkeypatch, results)
    assert main(["doctor"]) == code
    out = capsys.readouterr().out
    assert all(s in out for s in present) and not any(s in out for s in absent)


HOME = NetInfo("eth0", "192.168.1.100", "192.168.1.1", "192.168.1.0/24")
LAPTOP = Device("192.168.1.10", "AA:BB:CC:DD:EE:10", "Dell", "laptop")
PHONE = Device("192.168.1.50", "BB:BB:BB:BB:BB:BB", "Apple", "phone")


def _patch_sweep(monkeypatch, result):
    calls = {}

    def sweep(target=None, **kwargs):
        calls["target"] = target
        calls["kwargs"] = kwargs
        if isinstance(result, Exception):
            raise result
        return result

    monkeypatch.setattr(devices, "sweep", sweep)
    return calls


def _patch_lookup(monkeypatch, result):
    calls = {}

    def get_device(target=None, *, ip=None, mac=None, **kwargs):
        calls["target"] = target
        calls["ip"] = ip
        calls["mac"] = mac
        calls["kwargs"] = kwargs
        if isinstance(result, Exception):
            raise result
        return result

    monkeypatch.setattr(devices, "get_device", get_device)
    return calls


def test_devices_broken_pipe_exits_quietly(monkeypatch, capsys):
    """``homenet devices | head`` exits 1 and does not print a traceback."""
    _patch_detect(monkeypatch, HOME)
    _patch_sweep(monkeypatch, [PHONE, LAPTOP])
    read_fd, write_fd = os.pipe()
    os.close(read_fd)
    monkeypatch.setattr(sys, "stdout", os.fdopen(write_fd, "w", encoding="utf-8"))
    with pytest.raises(SystemExit) as caught:
        main(["devices"])
    assert caught.value.code == 1
    assert capsys.readouterr().err == ""
    assert os.readlink(f"/proc/self/fd/{write_fd}") == os.devnull


def test_devices_prints_the_banner_and_the_sweep(capsys, monkeypatch):
    _patch_detect(monkeypatch, HOME)
    calls = _patch_sweep(monkeypatch, [PHONE, LAPTOP])
    assert main(["devices"]) == 0
    captured = capsys.readouterr()
    assert calls["target"] == "192.168.1.0/24"
    assert calls["kwargs"] == {"local_network": "192.168.1.0/24", "resolve_names": True}
    assert captured.out == (
        "·\n" * 2 + f"{BANNER}\n\n{format_devices([PHONE, LAPTOP])}" + "\n" + "·\n" * 5
    )
    assert captured.err == ""
    assert "not implemented" not in captured.out


def test_devices_json_has_no_banner(capsys, monkeypatch):
    hostile = Device("192.168.1.5", 'aa"bb', "v\\endor", "x\x1b[2Jy")
    _patch_detect(monkeypatch, HOME)
    _patch_sweep(monkeypatch, [hostile])
    assert main(["devices", "--json"]) == 0
    captured = capsys.readouterr()
    assert captured.out == format_devices_json([hostile]) + "\n"
    assert captured.err == ""
    assert BANNER not in captured.out
    assert "\x1b" not in captured.out
    assert json.loads(captured.out)["devices"][0]["hostname"] == "x?[2Jy"


def test_devices_labels_this_computer(capsys, monkeypatch):
    mac = "b8:27:eb:aa:bb:cc"
    me = Device("192.168.1.20", None, None, None)
    other = Device("192.168.1.50", None, None, None)
    _patch_detect(
        monkeypatch, NetInfo("eth0", "192.168.1.20", "192.168.1.1", "192.168.1.0/24", mac=mac)
    )
    _patch_sweep(monkeypatch, [other, me])
    assert main(["devices"]) == 0
    rows = [line for line in capsys.readouterr().out.splitlines() if line[:3].isdigit()]
    mine = next(line for line in rows if line.startswith("192.168.1.20"))
    theirs = next(line for line in rows if line.startswith("192.168.1.50"))
    assert "this computer" in mine and mac in mine
    assert "this computer" not in theirs and mac not in theirs
    assert "unknown" in theirs


@pytest.mark.parametrize(
    ("mac", "expected"),
    [("b8:27:eb:aa:bb:cc", "b8:27:eb:aa:bb:cc"), (None, None)],
    ids=["filled", "blank"],
)
def test_devices_json_marks_this_computer(mac, expected, capsys, monkeypatch):
    me = Device("192.168.1.20", None, None, None)
    other = Device("192.168.1.10", "AA:BB:CC:DD:EE:10", "Dell", "laptop")
    plain = json.loads(format_devices_json([me, other]))
    base = {item["ip"]: item for item in plain["devices"]}
    _patch_detect(
        monkeypatch, NetInfo("eth0", "192.168.1.20", "192.168.1.1", "192.168.1.0/24", mac=mac)
    )
    _patch_sweep(monkeypatch, [me, other])
    assert main(["devices", "--json"]) == 0
    by_ip = {item["ip"]: item for item in json.loads(capsys.readouterr().out)["devices"]}
    assert by_ip["192.168.1.10"] == base["192.168.1.10"]
    assert "is_self" not in by_ip["192.168.1.10"]
    row = dict(by_ip["192.168.1.20"])
    assert row.pop("is_self") is True
    assert row.pop("mac") == expected
    unchanged = dict(base["192.168.1.20"])
    unchanged.pop("mac")
    assert row == unchanged


@pytest.mark.parametrize(
    ("command", "hint"),
    [
        ("devices", "Try: sudo apt install nmap"),
        ("device", "Try: sudo apt install nmap"),
        ("baseline", "Check that the folder is writable."),
    ],
)
def test_errors_show_a_hint_without_a_traceback(command, hint, capsys, monkeypatch):
    _patch_detect(monkeypatch, HOME)
    if command == "baseline":
        _patch_sweep(monkeypatch, [LAPTOP])

        def save(found, path=None, now=None):
            raise BaselineError(f"Could not save the baseline to /tmp/baseline.json: {hint}", hint)

        monkeypatch.setattr(baseline, "save_baseline", save)
        argv = ["baseline"]
        phrase = "Could not save the baseline"
    else:
        error = NmapNotFoundError("nmap is not installed.", hint)
        argv = ["devices"] if command == "devices" else ["device", "192.168.1.10"]
        if command == "devices":
            _patch_sweep(monkeypatch, error)
        else:
            _patch_lookup(monkeypatch, error)
        phrase = "nmap is not installed."
    assert main(argv) == 1
    captured = capsys.readouterr()
    assert phrase in captured.out
    assert f"Fix: {hint}" in captured.out
    assert "Traceback" not in captured.out
    assert "Traceback" not in captured.err
    assert "NmapNotFoundError" not in captured.out
    assert "BaselineError" not in captured.out


@pytest.mark.parametrize(
    ("subnet", "phrase"),
    [
        (None, "Could not detect your home network."),
        ("fe80::/64", "is not IPv4"),
        ("not-a-network", "is not a valid subnet"),
    ],
)
def test_devices_refuses_a_home_network_it_cannot_scan(subnet, phrase, capsys, monkeypatch):
    _patch_detect(monkeypatch, NetInfo("eth0", None, None, subnet))
    calls = _patch_sweep(monkeypatch, [LAPTOP])
    assert main(["devices"]) == 1
    captured = capsys.readouterr()
    assert calls == {}  # nothing scanned
    assert phrase in captured.out and "Fix:" in captured.out
    assert "Traceback" not in captured.out + captured.err


def test_device_looks_up_one_address(capsys, monkeypatch):
    _patch_detect(monkeypatch, HOME)
    calls = _patch_lookup(monkeypatch, LAPTOP)
    assert main(["device", "192.168.1.10"]) == 0
    captured = capsys.readouterr()
    assert calls["target"] == "192.168.1.0/24"
    assert calls["ip"] == "192.168.1.10"
    assert calls["mac"] is None
    assert calls["kwargs"] == {"local_network": "192.168.1.0/24", "resolve_names": True}
    assert captured.out == "·\n" * 2 + f"{BANNER}\n\n{format_device(LAPTOP)}" + "\n" + "·\n" * 5
    assert captured.err == ""


def test_device_json_prints_one_object(capsys, monkeypatch):
    _patch_detect(monkeypatch, HOME)
    _patch_lookup(monkeypatch, LAPTOP)
    assert main(["device", "192.168.1.10", "--json"]) == 0
    captured = capsys.readouterr()
    assert captured.out == format_device_json(LAPTOP) + "\n"
    assert captured.err == ""
    assert BANNER not in captured.out
    assert set(json.loads(captured.out)) == {"hostname", "ip", "mac", "ports", "vendor"}


def test_device_not_found_is_a_friendly_error(capsys, monkeypatch):
    _patch_detect(monkeypatch, HOME)
    _patch_lookup(monkeypatch, None)
    assert main(["device", "192.168.1.20"]) == 1
    captured = capsys.readouterr()
    assert "No device was found at 192.168.1.20." in captured.out
    assert "Fix: Run `homenet devices`" in captured.out
    assert "Traceback" not in captured.out
    assert BANNER in captured.out


@pytest.mark.parametrize(
    ("ip", "phrase"),
    [("192.168.1.1\x1b[2J", "not a valid IP address"), ("2001:db8::1", "not an IPv4 address")],
    ids=["garbage", "ipv6"],
)
def test_device_rejects_a_bad_address_without_scanning(ip, phrase, capsys, monkeypatch):
    calls = _patch_lookup(monkeypatch, LAPTOP)
    assert main(["device", ip]) == 1
    out = capsys.readouterr().out
    assert calls == {}
    assert phrase in out and "Fix:" in out and "\x1b" not in out


def test_baseline_saves_the_sweep(capsys, monkeypatch, tmp_path):
    _patch_detect(monkeypatch, HOME)
    calls = _patch_sweep(monkeypatch, [LAPTOP])
    saved = {}

    def save(found, path=None, now=None):
        saved["devices"] = list(found)
        return tmp_path / "baseline.json"

    monkeypatch.setattr(baseline, "save_baseline", save)
    assert main(["baseline"]) == 0
    captured = capsys.readouterr()
    assert calls["kwargs"]["resolve_names"] is True
    assert saved["devices"] == [LAPTOP]
    assert f"Saved 1 device to {tmp_path / 'baseline.json'}." in captured.out
    assert "Compare later with `homenet new-devices`." in captured.out
    assert BANNER in captured.out
    assert captured.err == ""


@pytest.mark.parametrize(
    ("case", "code", "json_mode"),
    [
        ("same", 0, False),
        ("changed", 1, False),
        ("missing", 2, False),
        ("scan-error", 2, False),
        ("changed", 1, True),
        ("missing", 2, True),
    ],
)
def test_new_devices_exit_codes(case, code, json_mode, capsys, monkeypatch):
    current = [LAPTOP, PHONE] if case == "changed" else [LAPTOP]
    calls = _patch_sweep(
        monkeypatch,
        NmapNotFoundError("nmap is not installed.", "Try: sudo apt install nmap")
        if case == "scan-error"
        else current,
    )
    if case == "missing":

        def load():
            raise BaselineNotFoundError("No baseline saved yet.", "Run `homenet baseline` first.")

        monkeypatch.setattr(baseline, "load_baseline", load)
    else:
        _patch_detect(monkeypatch, HOME)
        monkeypatch.setattr(baseline, "load_baseline", lambda path=None: [LAPTOP])
    argv = ["new-devices", "--json"] if json_mode else ["new-devices"]
    assert main(argv) == code
    captured = capsys.readouterr()
    assert "Traceback" not in captured.out
    assert "Traceback" not in captured.err
    if case == "missing":
        assert calls == {}
    if code == 2:
        assert "BaselineNotFoundError" not in captured.out + captured.err
        assert "NmapNotFoundError" not in captured.out + captured.err
        if json_mode:
            assert captured.out == ""
            assert BANNER not in captured.err
            err = json.loads(captured.err)
            assert set(err) == {"error", "fix_hint"}
            assert err["fix_hint"]
        else:
            assert captured.err == ""
            assert captured.out.startswith("·\n" * 2 + BANNER + "\n")
            assert "Fix:" in captured.out
        return
    report = diff_devices([LAPTOP], current)
    assert captured.err == ""
    if json_mode:
        assert captured.out == format_diff_json(report) + "\n"
        assert json.loads(captured.out)["has_changes"] is (code == 1)
        assert BANNER not in captured.out
    else:
        assert captured.out == "·\n" * 2 + f"{BANNER}\n\n{format_diff(report)}" + "\n" + "·\n" * 5


def test_whoami_json_prints_netinfo(capsys, monkeypatch):
    _patch_detect(monkeypatch, HOME)
    assert main(["whoami-net", "--json"]) == 0
    captured = capsys.readouterr()
    assert captured.out == format_whoami_json(HOME) + "\n"
    assert captured.err == ""
    loaded = json.loads(captured.out)
    assert (loaded["ip"], loaded["prefix"]) == (HOME.ip, 24)
    assert f"IP address    {loaded['ip']}" in format_whoami(HOME)
    assert BANNER not in captured.out
    assert "This computer" not in captured.out


@pytest.mark.parametrize(
    ("command", "message", "hint"),
    [
        (
            "whoami-net",
            "No default route\x1b found.",
            "Connect to Wi-Fi or Ethernet and try again.",
        ),
        ("devices", "nmap output was incomplete or corrupted.", None),
        ("new-devices", "No baseline saved yet.", "Run `homenet baseline` first."),
    ],
)
def test_json_errors_go_to_stderr(command, message, hint, capsys, monkeypatch):
    if command == "whoami-net":
        _patch_detect(monkeypatch, NetInfoError(message, hint))
    elif command == "devices":
        _patch_detect(monkeypatch, HOME)
        _patch_sweep(monkeypatch, ParseError(message, hint))
    else:

        def load():
            raise BaselineNotFoundError(message, hint)

        monkeypatch.setattr(baseline, "load_baseline", load)
    code = 2 if command == "new-devices" else 1
    assert main([command, "--json"]) == code
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == format_error_json(message, hint) + "\n"
    assert set(json.loads(captured.err)) == {"error", "fix_hint"}
    assert "\x1b" not in captured.err
    assert BANNER not in captured.err
    assert "Traceback" not in captured.err


@pytest.mark.parametrize(
    ("results", "code", "ok"),
    [
        (
            [
                CheckResult("nmap", True, "nmap 7.95", severity="ok"),
                CheckResult("ip", True, "ip 6.1.0", severity="ok"),
            ],
            0,
            True,
        ),
        (
            [CheckResult("privileges", False, "user on eth0\x1b", "Re-run", "warning")],
            0,
            True,
        ),
        (
            [
                CheckResult("nmap", False, "missing", "sudo apt install nmap", "error"),
                CheckResult("privileges", False, "normal user", "Re-run with sudo", "warning"),
            ],
            1,
            False,
        ),
    ],
    ids=("pass", "warning", "error"),
)
def test_doctor_json(results, code, ok, capsys, monkeypatch):
    _patch_checks(monkeypatch, results)
    assert main(["doctor", "--json"]) == code
    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out == format_doctor_json(results) + "\n"
    loaded = json.loads(captured.out)
    assert loaded["ok"] is ok
    assert "\x1b" not in captured.out
    if code == 0 and len(results) == 2:
        assert [item["name"] for item in loaded["checks"]] == ["nmap", "ip"]
    if any(result.severity == "warning" and not result.ok for result in results):
        warning = next(item for item in loaded["checks"] if item["severity"] == "warning")
        assert warning["fix_hint"]
    if code == 1:
        assert loaded["checks"][0]["fix_hint"] == "sudo apt install nmap"
        assert loaded["checks"][1]["severity"] == "warning"
    if any("\x1b" in result.detail for result in results):
        assert loaded["checks"][0]["detail"] == "user on eth0?"


def _assert_no_controls(value) -> None:
    if isinstance(value, str):
        assert "\x1b" not in value
    elif isinstance(value, dict):
        for item in value.values():
            _assert_no_controls(item)
    elif isinstance(value, list):
        for item in value:
            _assert_no_controls(item)


def test_wifi_on_wsl_exits_zero(capsys, monkeypatch):
    info = WifiInfo(False, "WSL", wsl=True)
    monkeypatch.setattr(wifi, "get_wifi_info", lambda **_kwargs: info)
    assert main(["wifi"]) == 0
    assert capsys.readouterr().out == "·\n" * 2 + format_wifi(info) + "\n" + "·\n" * 5


def _wifi_json_ok(loaded: dict, seen: dict) -> None:
    assert loaded["available"] is True and loaded["signal"]
    assert seen["wifi"]["on_step"] is not None and "stats_every" not in seen["wifi"]


def _dns_json_ok(loaded: dict, seen: dict) -> None:
    assert loaded["servers"][0]["ip"] == "192.168.1.1?"
    assert loaded["lookup"]["ok"] is True
    assert seen["dns"]["on_step"] is not None and "stats_every" not in seen["dns"]
    assert seen["lookup"]["on_step"] is not None and "stats_every" not in seen["lookup"]


@pytest.mark.parametrize(
    ("command", "step", "render", "expect"),
    [
        (
            "wifi",
            "Reading Wi-Fi link of wlan0 (iw)",
            lambda info, _config, _lookup: format_wifi_json(info),
            _wifi_json_ok,
        ),
        (
            "dns",
            "Looking up example.com",
            lambda _info, config, lookup: format_dns_json(config, lookup, HOME.gateway),
            _dns_json_ok,
        ),
    ],
)
def test_wifi_and_dns_json(command, step, render, expect, capsys, monkeypatch):
    info = WifiInfo(
        True,
        interface="wlan0",
        ssid="Home\x1b[2J",
        signal_dbm=-55,
        signal_percent=90,
        channel=36,
        frequency_mhz=5180,
        band="5 GHz",
        link_speed_mbps=866.7,
    )
    config = DnsConfig(
        [DnsServer("192.168.1.1\x1b", "resolvectl", "wlan0")],
        "resolvectl",
        False,
        ["1.1.1.1"],
    )
    lookup = LookupResult("example.com", True, ("93.184.216.34",), 12.5)
    seen: dict = {}

    def get_wifi(**kwargs):
        seen["wifi"] = kwargs
        kwargs["on_step"]("Reading Wi-Fi link of wlan0 (iw)")
        return info

    def get_dns(**kwargs):
        seen["dns"] = kwargs
        kwargs["on_step"]("Asking systemd-resolved (resolvectl)")
        return config

    def lookup_test(*_args, **kwargs):
        seen["lookup"] = kwargs
        kwargs["on_step"]("Looking up example.com")
        return lookup

    monkeypatch.setattr(wifi, "get_wifi_info", get_wifi)
    monkeypatch.setattr(dns, "get_dns_servers", get_dns)
    monkeypatch.setattr(dns, "dns_lookup_test", lookup_test)
    monkeypatch.setattr(netinfo, "detect", lambda: HOME)
    monkeypatch.setattr(cli, "is_wsl", lambda: False)
    assert main([command, "-v", "--json"]) == 0
    captured = capsys.readouterr()
    assert captured.out and BANNER not in captured.out
    loaded = json.loads(captured.out)
    _assert_no_controls(loaded)
    assert captured.out == render(info, config, lookup) + "\n"
    assert step in captured.err
    expect(loaded, seen)


def test_doctor_includes_optional_tool_checks(capsys, monkeypatch):
    monkeypatch.setattr(
        checks,
        "run_all_checks",
        lambda: [CheckResult("nmap", True, "nmap 7.95", severity="ok")],
    )
    seen: list[str] = []

    def fake(name, **_kwargs):
        seen.append(name)
        return CheckResult(name, False, f"{name} is not installed", "sudo apt install x", "warning")

    monkeypatch.setattr(checks, "check_optional_tool", fake)
    assert main(["doctor"]) == 0
    out = capsys.readouterr().out
    assert seen == ["nmcli", "iw", "resolvectl"]
    assert "WARN  nmcli" in out and "WARN  iw" in out and "WARN  resolvectl" in out
    assert "No errors. 3 warnings." in out
    assert "FAIL" not in out


_OTHER = Device("192.168.1.50", None, None, "phone", [Port(9, "tcp", "open", "discard")])
_OPEN = Device(
    "192.168.1.1",
    None,
    None,
    "r\x1bouter",
    [
        Port(80, "tcp", "open", "http"),
        Port(22, "tcp", "open", "ssh", "Drop\x1bbear", "2022.83"),
        Port(443, "tcp", "filtered"),
    ],
)
_QUIET = Device("192.168.1.20", None, None, None, [Port(22, "tcp", "closed", "ssh")])
_ROUTER = RouterCheck(
    "192.168.1.1",
    [
        AdminPage("http://192.168.1.1/", 80, True, True, 200, "Router\x1b Login", "lighttpd"),
        AdminPage("https://192.168.1.1/", 443, True, False, 401, None, None),
    ],
)
_ROUTER_QUIET = RouterCheck(
    "192.168.1.1",
    [AdminPage("http://192.168.1.1/", 80, False, True, error="connection refused")],
)
_SPEED = SpeedResult(8.0, 1_000_000, 1.0, "https://speed.cloudflare.com/__down?bytes=1000000\x1b")
_COMMANDS = ("ports", "services", "router", "speed")


def _patch_command(monkeypatch, command, result):
    calls = {}

    def scan(target=None, **kwargs):
        calls["target"] = target
        calls["kwargs"] = kwargs
        if isinstance(result, Exception):
            raise result
        return result

    def check(*args, **kwargs):
        calls["args"] = args
        calls["kwargs"] = kwargs
        if isinstance(result, Exception):
            raise result
        return result

    def measure(**kwargs):
        calls["kwargs"] = kwargs
        if isinstance(result, Exception):
            raise result
        return result

    if command == "ports":
        monkeypatch.setattr(ports, "scan_ports", scan)
    elif command == "services":
        monkeypatch.setattr(ports, "scan_services", scan)
    elif command == "router":
        monkeypatch.setattr(router, "check_router_admin", check)
    else:
        monkeypatch.setattr(speed, "measure_download", measure)
    return calls


def _render(command, result, json_mode):
    if command == "ports":
        notes = port_notes.notes_for_ports(result.ports)
        return format_ports_json(result, notes) if json_mode else format_ports(result, notes)
    if command == "services":
        return format_services_json(result) if json_mode else format_services(result)
    if command == "router":
        return format_router_json(result) if json_mode else format_router(result)
    return format_speed_json(result) if json_mode else format_speed(result)


def _assert_call(command, calls, *, json_mode):
    if command in ("ports", "services"):
        assert calls["target"] == "192.168.1.1"
        assert calls["kwargs"] == {"top_ports": 100}
        assert "allow_subnet" not in calls["kwargs"]
    elif command == "router":
        assert calls["args"] == () and calls["kwargs"] == {}
    elif json_mode:
        assert calls == {"kwargs": {}}
    else:
        assert set(calls["kwargs"]) == {"on_progress"}
        assert callable(calls["kwargs"]["on_progress"])


@pytest.mark.parametrize("json_mode", (False, True), ids=("plain", "json"))
@pytest.mark.parametrize("command", _COMMANDS)
def test_command_success(command, json_mode, capsys, monkeypatch):
    result = {
        "ports": [_OPEN, _OTHER],
        "services": [_OPEN, _OTHER],
        "router": _ROUTER,
        "speed": _SPEED,
    }[command]
    shown = _OPEN if command in ("ports", "services") else result
    calls = _patch_command(monkeypatch, command, result)
    argv = {
        "ports": ["ports", "192.168.1.1"],
        "services": ["services", "192.168.1.1"],
        "router": ["router"],
        "speed": ["speed"],
    }[command]
    assert main([*argv, "--json"] if json_mode else argv) == 0
    captured = capsys.readouterr()
    rendered = _render(command, shown, json_mode)
    if json_mode:
        assert captured.out == rendered + "\n"
        assert BANNER not in captured.out
    elif command == "speed":
        assert captured.out == "·\n" * 2 + rendered + "\n" + "·\n" * 5
        assert BANNER not in captured.out
    else:
        assert captured.out == "·\n" * 2 + f"{BANNER}\n\n{rendered}" + "\n" + "·\n" * 5
    assert captured.err == ""
    assert "\x1b" not in captured.out
    _assert_call(command, calls, json_mode=json_mode)


@pytest.mark.parametrize("json_mode", (False, True), ids=("plain", "json"))
@pytest.mark.parametrize(
    ("command", "phrase"),
    [
        ("ports", "No open ports were found."),
        ("services", "No running services were identified."),
        ("router", "No admin page answered"),
    ],
)
def test_quiet_result_still_succeeds(command, phrase, json_mode, capsys, monkeypatch):
    result = _ROUTER_QUIET if command == "router" else [_QUIET]
    shown = _ROUTER_QUIET if command == "router" else _QUIET
    _patch_command(monkeypatch, command, result)
    argv = ["router"] if command == "router" else [command, "192.168.1.20"]
    assert main([*argv, "--json"] if json_mode else argv) == 0
    captured = capsys.readouterr()
    rendered = _render(command, shown, json_mode)
    if json_mode:
        assert captured.out == rendered + "\n"
        assert BANNER not in captured.out
    else:
        assert captured.out == "·\n" * 2 + f"{BANNER}\n\n{rendered}" + "\n" + "·\n" * 5
        assert phrase in captured.out


@pytest.mark.parametrize("json_mode", (False, True), ids=("plain", "json"))
@pytest.mark.parametrize("command", _COMMANDS)
def test_command_errors(command, json_mode, capsys, monkeypatch):
    if command == "speed":
        argv, error = (
            ["speed"],
            SpeedError("Could not measure your internet speed.", "Check the internet."),
        )
    elif command == "router":
        argv, error = (
            ["router"],
            TargetNotAllowedError(
                "Could not detect your router (default gateway).",
                "Check you are connected (see `homenet whoami-net`).",
            ),
        )
    else:
        argv, error = (
            [command, "192.168.1.1"],
            NmapNotFoundError("nmap is not installed.", "Try: sudo apt install nmap"),
        )
    _patch_command(monkeypatch, command, error)
    assert main([*argv, "--json"] if json_mode else argv) == 1
    captured = capsys.readouterr()
    assert "Traceback" not in captured.out + captured.err
    assert type(error).__name__ not in captured.out + captured.err
    if json_mode:
        assert captured.out == ""
        assert captured.err == format_error_json(str(error), error.hint) + "\n"
        assert set(json.loads(captured.err)) == {"error", "fix_hint"}
        assert BANNER not in captured.err
    else:
        assert f"Fix: {error.hint}" in captured.out
        assert (BANNER in captured.out) is (command != "speed")


@pytest.mark.parametrize(
    ("command", "ip", "phrase", "json_mode"),
    [
        ("ports", "192.168.1.0/24", "is a subnet", False),
        ("ports", "router.lan", "not a valid IP address", False),
        ("ports", "2001:db8::1", "not an IPv4 address", False),
        ("services", "192.168.1.0/24", "is a subnet", False),
        ("ports", "192.168.1.0/24", "is a subnet", True),
    ],
)
def test_host_commands_reject_a_bad_target(command, ip, phrase, json_mode, capsys, monkeypatch):
    calls = _patch_command(monkeypatch, command, [_OPEN])
    assert main([command, ip, "--json"] if json_mode else [command, ip]) == 1
    captured = capsys.readouterr()
    assert calls == {}
    assert "Traceback" not in captured.out + captured.err
    blob = captured.err if json_mode else captured.out
    assert phrase in blob and ("fix_hint" in blob if json_mode else "Fix:" in blob)
    if json_mode:
        assert captured.out == ""
        assert set(json.loads(captured.err)) == {"error", "fix_hint"}


@pytest.mark.parametrize("json_mode", (False, True), ids=("plain", "json"))
@pytest.mark.parametrize("command", ("ports", "services"))
def test_host_commands_say_when_nothing_answered(command, json_mode, capsys, monkeypatch):
    _patch_command(monkeypatch, command, [])
    assert main([command, "192.168.1.9", "--json"] if json_mode else [command, "192.168.1.9"]) == 1
    captured = capsys.readouterr()
    assert "No device answered at 192.168.1.9." in (captured.err if json_mode else captured.out)
    if json_mode:
        assert captured.out == ""
        assert set(json.loads(captured.err)) == {"error", "fix_hint"}
    else:
        assert "Fix:" in captured.out and BANNER in captured.out


def test_json_usage_error_prints_an_error_object(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["ports", "--json"])
    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    loaded = json.loads(captured.err)
    assert set(loaded) == {"error", "fix_hint"}
    assert "required" in loaded["error"] and loaded["fix_hint"]
    assert "usage:" not in captured.err and "Traceback" not in captured.err

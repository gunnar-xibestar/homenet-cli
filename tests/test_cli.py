"""CLI help text and doctor exit codes. Core checks are mocked."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from homenet.cli import BANNER, main
from homenet.core import baseline, checks, devices, netinfo, port_notes, ports, router, speed
from homenet.core.baseline import BaselineError, BaselineNotFoundError, diff_devices
from homenet.core.checks import CheckResult
from homenet.core.netinfo import NetInfo, NetInfoError
from homenet.core.parser import Device, ParseError, Port
from homenet.core.router import AdminPage, RouterCheck
from homenet.core.runner import NmapNotFoundError, TargetNotAllowedError
from homenet.core.speed import SpeedError, SpeedResult
from homenet.output import (
    format_device,
    format_device_json,
    format_devices,
    format_devices_json,
    format_diff,
    format_diff_json,
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
)

ROOT = Path(__file__).resolve().parents[1]

COMMANDS = (
    "whoami-net",
    "devices",
    "device",
    "ports",
    "services",
    "router",
    "baseline",
    "new-devices",
    "speed",
    "doctor",
)

SCAN_COMMANDS = (
    "whoami-net",
    "devices",
    "device",
    "ports",
    "services",
    "router",
    "baseline",
    "new-devices",
)

EXAMPLES = {
    "whoami-net": "homenet whoami-net",
    "devices": "homenet devices",
    "device": "homenet device 192.168.1.20",
    "ports": "homenet ports 192.168.1.1",
    "services": "homenet services 192.168.1.1",
    "router": "homenet router",
    "baseline": "homenet baseline",
    "new-devices": "homenet new-devices",
    "speed": "homenet speed",
    "doctor": "homenet doctor",
}

# Wording from homenet.core.checks.check_privileges (cap_net_raw+eip, no $(which)).
PRIVILEGE_HINT = (
    "Easiest: re-run with sudo, e.g. `sudo homenet scan`. "
    "Advanced alternative: `sudo setcap cap_net_raw+eip /usr/bin/nmap` (use the path "
    "from `command -v nmap`) and run nmap with --privileged. Be careful: this lets "
    "every user on this computer send raw network packets through nmap, not just you."
)


def _load_toml(text: str) -> dict:
    """tomllib is stdlib on 3.11+; Python 3.10 uses the tomli dependency."""
    try:
        import tomllib
    except ModuleNotFoundError:
        import tomli as tomllib

    return tomllib.loads(text)


WHAT_IT_DOES = {
    "whoami-net": "IP address",
    "devices": "phones",
    "device": "single device",
    "ports": "open port",
    "services": "web server",
    "router": "internet",
    "baseline": "snapshot",
    "new-devices": "anything new",
    "speed": "internet",
    "doctor": "nmap",
}


def test_console_script_entry_point():
    data = _load_toml((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert data["project"]["scripts"]["homenet"] == "homenet.cli:main"
    dev = data["project"]["optional-dependencies"]["dev"]
    assert any(item.startswith("tomli") for item in dev)


def test_top_level_help_lists_commands_and_banner(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert BANNER in out
    for command in COMMANDS:
        assert command in out
    for line in out.splitlines():
        if "whoami-net" in line:
            assert "Show this computer's address" in line
        if line.strip().startswith("new-devices"):
            assert "saved snapshot" in line


@pytest.mark.parametrize("command", COMMANDS)
def test_command_help_says_what_it_does_and_gives_an_example(command, capsys):
    with pytest.raises(SystemExit) as exc:
        main([command, "--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert WHAT_IT_DOES[command] in out
    assert "Example:" in out
    assert EXAMPLES[command] in out
    if command in SCAN_COMMANDS:
        assert BANNER in out
    if command == "doctor":
        assert "ping" in out


@pytest.mark.parametrize("command", ("device", "ports", "services"))
def test_ip_commands_require_an_address(command):
    with pytest.raises(SystemExit) as exc:
        main([command])
    assert exc.value.code == 2


def test_missing_command_is_an_error():
    with pytest.raises(SystemExit) as exc:
        main([])
    assert exc.value.code != 0


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


def test_whoami_net_prints_core_netinfo(capsys, monkeypatch):
    info = NetInfo("wlp2s0", "192.168.1.100", "192.168.1.1", "192.168.1.0/24")
    _patch_detect(monkeypatch, info)
    assert main(["whoami-net"]) == 0
    captured = capsys.readouterr()
    assert captured.out == format_whoami(info) + "\n"
    assert captured.err == ""
    assert "192.168.1.100/24" in captured.out
    assert "not implemented" not in captured.out


def test_whoami_net_reports_a_missing_address(capsys, monkeypatch):
    info = NetInfo("wlp2s0", None, "192.168.1.1", "192.168.1.0/24")
    _patch_detect(monkeypatch, info)
    assert main(["whoami-net"]) == 0
    out = capsys.readouterr().out
    assert "not available" in out
    assert "This computer's own IP address was not available." in out
    assert "192.168.1.1" in out


def test_whoami_net_error_shows_a_hint_without_a_traceback(capsys, monkeypatch):
    error = NetInfoError(
        "No default route found; you may not be connected to a network.",
        "Connect to Wi-Fi or Ethernet and try again.",
    )
    _patch_detect(monkeypatch, error)
    assert main(["whoami-net"]) == 1
    captured = capsys.readouterr()
    assert captured.out == format_error(str(error), error.hint) + "\n"
    assert "Fix: Connect to Wi-Fi or Ethernet and try again." in captured.out
    assert "Traceback" not in captured.out
    assert "Traceback" not in captured.err
    assert "NetInfoError" not in captured.out


def test_whoami_net_error_without_a_hint(capsys, monkeypatch):
    error = NetInfoError("Unexpected output from `ip -j route` (expected a list).")
    _patch_detect(monkeypatch, error)
    assert main(["whoami-net"]) == 1
    captured = capsys.readouterr()
    assert captured.out == "Unexpected output from `ip -j route` (expected a list).\n"
    assert "Fix:" not in captured.out
    assert "Traceback" not in captured.out
    assert "Traceback" not in captured.err


def _patch_checks(monkeypatch, results: list[CheckResult]) -> None:
    monkeypatch.setattr(checks, "run_all_checks", lambda: results)


def test_doctor_exits_0_when_every_check_passes(capsys, monkeypatch):
    _patch_checks(
        monkeypatch,
        [
            CheckResult("nmap", True, "nmap 7.95"),
            CheckResult("ip", True, "ip 6.1.0"),
            CheckResult("privileges", True, "running as root"),
            CheckResult("network", True, "default route via 192.168.1.1, interface eth0 (up)"),
        ],
    )
    assert main(["doctor"]) == 0
    out = capsys.readouterr().out
    assert "PASS" in out
    assert "FAIL" not in out
    assert "nmap 7.95" in out
    assert "All 4 checks passed." in out
    assert BANNER not in out
    nmap_at = out.index("PASS  nmap")
    ip_at = out.index("PASS  ip")
    privileges_at = out.index("PASS  privileges")
    network_at = out.index("PASS  network")
    assert nmap_at < ip_at < privileges_at < network_at


def test_doctor_exits_1_and_shows_fix_hints_when_a_check_fails(capsys, monkeypatch):
    _patch_checks(
        monkeypatch,
        [
            CheckResult(
                "nmap",
                False,
                "nmap is not installed (not found on PATH).",
                "sudo apt install nmap",
            ),
            CheckResult("ip", True, "ip 6.1.0"),
            CheckResult(
                "privileges",
                False,
                "running as a normal user",
                PRIVILEGE_HINT,
            ),
            CheckResult("network", True, "default route via 192.168.1.1, interface eth0 (up)"),
        ],
    )
    assert main(["doctor"]) == 1
    out = capsys.readouterr().out
    assert "FAIL  nmap" in out
    assert "PASS  ip" in out
    assert "Fix: sudo apt install nmap" in out
    assert "setcap cap_net_raw+eip" in out
    assert "$(which nmap)" not in out
    assert "2 checks failed." in out


def test_doctor_treats_warnings_as_non_fatal(capsys, monkeypatch):
    _patch_checks(
        monkeypatch,
        [
            CheckResult("nmap", True, "nmap 7.95", severity="ok"),
            CheckResult("ip", True, "ip 6.1.0", severity="ok"),
            CheckResult(
                "privileges",
                False,
                "running as a normal user",
                PRIVILEGE_HINT,
                "warning",
            ),
            CheckResult("network", True, "default route via eth0", severity="ok"),
            CheckResult("ping", True, "ping 3.12", severity="ok"),
        ],
    )
    assert main(["doctor"]) == 0
    out = capsys.readouterr().out
    assert "WARN  privileges" in out
    assert "FAIL" not in out
    assert "setcap cap_net_raw+eip" in out
    assert "sudo homenet scan" in out
    assert "$(which nmap)" not in out
    assert "No errors. 1 warning." in out


def test_doctor_exits_1_only_for_error_severity(capsys, monkeypatch):
    _patch_checks(
        monkeypatch,
        [
            CheckResult("nmap", False, "nmap is not installed", "sudo apt install nmap", "error"),
            CheckResult(
                "privileges",
                False,
                "running as a normal user",
                "Re-run with sudo",
                "warning",
            ),
        ],
    )
    assert main(["doctor"]) == 1
    out = capsys.readouterr().out
    assert "FAIL  nmap" in out
    assert "WARN  privileges" in out
    assert "1 check failed. 1 warning." in out


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


@pytest.mark.parametrize(
    "command",
    (
        "whoami-net",
        "devices",
        "device",
        "ports",
        "services",
        "router",
        "new-devices",
        "speed",
        "doctor",
    ),
)
def test_json_flag_is_documented_on_the_commands_that_print_it(command, capsys):
    with pytest.raises(SystemExit) as exc:
        main([command, "--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "--json" in out
    assert "Errors go to stderr" in out


@pytest.mark.parametrize("command", ("baseline",))
def test_other_commands_have_no_json_flag(command, capsys):
    with pytest.raises(SystemExit):
        main([command, "--help"])
    assert "--json" not in capsys.readouterr().out


def test_new_devices_help_documents_exit_codes(capsys):
    with pytest.raises(SystemExit):
        main(["new-devices", "--help"])
    out = capsys.readouterr().out
    assert "0 when nothing changed" in out
    assert "and 2 on error" in out


def test_devices_prints_the_banner_and_the_sweep(capsys, monkeypatch):
    _patch_detect(monkeypatch, HOME)
    calls = _patch_sweep(monkeypatch, [PHONE, LAPTOP])
    assert main(["devices"]) == 0
    captured = capsys.readouterr()
    assert calls["target"] == "192.168.1.0/24"
    assert calls["kwargs"] == {"local_network": "192.168.1.0/24", "resolve_names": True}
    assert captured.out == f"{BANNER}\n\n{format_devices([PHONE, LAPTOP])}\n"
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


def test_devices_explains_a_missing_home_network_without_scanning(capsys, monkeypatch):
    _patch_detect(monkeypatch, NetInfo("eth0", None, None, None))
    calls = _patch_sweep(monkeypatch, [LAPTOP])
    assert main(["devices"]) == 1
    captured = capsys.readouterr()
    assert calls == {}
    assert "Could not detect your home network." in captured.out
    assert "Fix: Connect to Wi-Fi or Ethernet, then try `homenet whoami-net`." in captured.out
    assert "Traceback" not in captured.out


@pytest.mark.parametrize(
    ("subnet", "phrase"),
    [("fe80::/64", "is not IPv4"), ("not-a-network", "is not a valid subnet")],
)
def test_devices_rejects_a_home_network_it_cannot_scan(subnet, phrase, capsys, monkeypatch):
    _patch_detect(monkeypatch, NetInfo("eth0", None, None, subnet))
    calls = _patch_sweep(monkeypatch, [LAPTOP])
    assert main(["devices"]) == 1
    captured = capsys.readouterr()
    assert calls == {}
    assert phrase in captured.out
    assert "Fix:" in captured.out
    assert "Traceback" not in captured.out
    assert "Traceback" not in captured.err


def test_device_looks_up_one_address(capsys, monkeypatch):
    _patch_detect(monkeypatch, HOME)
    calls = _patch_lookup(monkeypatch, LAPTOP)
    assert main(["device", "192.168.1.10"]) == 0
    captured = capsys.readouterr()
    assert calls["target"] == "192.168.1.0/24"
    assert calls["ip"] == "192.168.1.10"
    assert calls["mac"] is None
    assert calls["kwargs"] == {"local_network": "192.168.1.0/24", "resolve_names": True}
    assert captured.out == f"{BANNER}\n\n{format_device(LAPTOP)}\n"
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


def test_device_rejects_a_bad_address_without_scanning(capsys, monkeypatch):
    calls = _patch_lookup(monkeypatch, LAPTOP)
    assert main(["device", "192.168.1.1\x1b[2J"]) == 1
    captured = capsys.readouterr()
    assert calls == {}
    assert "\x1b" not in captured.out
    assert "not a valid IP address" in captured.out
    assert "Fix:" in captured.out
    assert "Traceback" not in captured.out


def test_device_rejects_ipv6(capsys, monkeypatch):
    calls = _patch_lookup(monkeypatch, LAPTOP)
    assert main(["device", "2001:db8::1"]) == 1
    out = capsys.readouterr().out
    assert calls == {}
    assert "not an IPv4 address" in out
    assert "homenet devices" in out


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


@pytest.mark.parametrize("json_mode", (False, True), ids=("plain", "json"))
@pytest.mark.parametrize(
    ("case", "code"),
    [("same", 0), ("changed", 1), ("missing", 2), ("scan-error", 2)],
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
        monkeypatch.setattr(baseline, "load_baseline", lambda: [LAPTOP])
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
            assert captured.out.startswith(BANNER + "\n")
            assert "Fix:" in captured.out
        return
    report = diff_devices([LAPTOP], current)
    assert captured.err == ""
    if json_mode:
        assert captured.out == format_diff_json(report) + "\n"
        assert json.loads(captured.out)["has_changes"] is (code == 1)
        assert BANNER not in captured.out
    else:
        assert captured.out == f"{BANNER}\n\n{format_diff(report)}\n"


def test_whoami_json_prints_netinfo(capsys, monkeypatch):
    _patch_detect(monkeypatch, HOME)
    assert main(["whoami-net", "--json"]) == 0
    captured = capsys.readouterr()
    assert captured.out == format_whoami_json(HOME) + "\n"
    assert captured.err == ""
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


def test_doctor_cleans_network_text_in_the_plain_report(capsys, monkeypatch):
    _patch_checks(
        monkeypatch,
        [CheckResult("network", False, "via eth0\x1b[2J", "Check wlan0\x1b]0;x\x07", "error")],
    )
    assert main(["doctor"]) == 1
    out = capsys.readouterr().out
    assert "\x1b" not in out
    assert "\x07" not in out
    assert "via eth0?[2J" in out
    assert "Fix: Check wlan0?]0;x?" in out


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


ROUTER_HOST = Device(
    "192.168.1.1",
    "aa:bb:cc:dd:ee:ff",
    "TP-Link",
    "router.lan",
    [
        Port(80, "tcp", "open", "http"),
        Port(443, "tcp", "filtered"),
        Port(53, "tcp", "open", "domain"),
    ],
)
OTHER_HOST = Device("192.168.1.50", None, None, "phone", [Port(9, "tcp", "open", "discard")])


def _patch_port_scan(monkeypatch, name, result):
    calls = {}

    def scan(target=None, **kwargs):
        calls["target"] = target
        calls["kwargs"] = kwargs
        if isinstance(result, Exception):
            raise result
        return result

    monkeypatch.setattr(ports, name, scan)
    return calls


def test_ports_scans_top_100_and_explains_open_ports(capsys, monkeypatch):
    calls = _patch_port_scan(monkeypatch, "scan_ports", [ROUTER_HOST, OTHER_HOST])
    seen = {}
    real = port_notes.notes_for_ports

    def wrapped(items):
        seen["ports"] = list(items)
        return real(items)

    monkeypatch.setattr(port_notes, "notes_for_ports", wrapped)
    assert main(["ports", "192.168.1.1"]) == 0
    captured = capsys.readouterr()
    assert calls["target"] == "192.168.1.1"
    assert calls["kwargs"] == {"top_ports": 100}
    assert seen["ports"] == ROUTER_HOST.ports
    notes = real(ROUTER_HOST.ports)
    assert captured.out == f"{BANNER}\n\n{format_ports(ROUTER_HOST, notes)}\n"
    assert captured.err == ""
    assert "risk: medium" in captured.out
    assert "Avoid entering passwords" in captured.out
    assert "192.168.1.50" not in captured.out
    assert "filtered" not in captured.out


def test_ports_json_has_no_banner(capsys, monkeypatch):
    hostile = Device(
        "192.168.1.1",
        None,
        None,
        "r\x1bouter",
        [Port(80, "tcp", "open", "http")],
    )
    _patch_port_scan(monkeypatch, "scan_ports", [hostile])
    assert main(["ports", "192.168.1.1", "--json"]) == 0
    captured = capsys.readouterr()
    notes = port_notes.notes_for_ports(hostile.ports)
    assert captured.out == format_ports_json(hostile, notes) + "\n"
    assert captured.err == ""
    assert BANNER not in captured.out
    assert "\x1b" not in captured.out
    assert json.loads(captured.out)["hostname"] == "r?outer"


def test_ports_with_no_open_ports_still_succeeds(capsys, monkeypatch):
    quiet = Device("192.168.1.20", None, None, None, [Port(22, "tcp", "closed", "ssh")])
    _patch_port_scan(monkeypatch, "scan_ports", [quiet])
    assert main(["ports", "192.168.1.20"]) == 0
    out = capsys.readouterr().out
    assert "No open ports were found." in out
    assert BANNER in out


def test_ports_error_shows_a_hint_without_a_traceback(capsys, monkeypatch):
    _patch_port_scan(
        monkeypatch,
        "scan_ports",
        NmapNotFoundError("nmap is not installed.", "Try: sudo apt install nmap"),
    )
    assert main(["ports", "192.168.1.1"]) == 1
    captured = capsys.readouterr()
    assert captured.out.startswith(BANNER + "\n")
    assert "Fix: Try: sudo apt install nmap" in captured.out
    assert "Traceback" not in captured.out
    assert "NmapNotFoundError" not in captured.out


def test_ports_json_error_is_an_object_on_stderr(capsys, monkeypatch):
    _patch_port_scan(
        monkeypatch,
        "scan_ports",
        ParseError("nmap output was incomplete.", "Try the scan again."),
    )
    assert main(["ports", "192.168.1.1", "--json"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert (
        captured.err
        == format_error_json("nmap output was incomplete.", "Try the scan again.") + "\n"
    )
    assert set(json.loads(captured.err)) == {"error", "fix_hint"}
    assert BANNER not in captured.err


@pytest.mark.parametrize(
    ("ip", "phrase"),
    [
        ("192.168.1.0/24", "is a subnet"),
        ("router.lan", "is not a valid IP address"),
        ("2001:db8::1", "is not an IPv4 address"),
    ],
)
def test_ports_rejects_a_bad_target_before_scanning(ip, phrase, capsys, monkeypatch):
    calls = _patch_port_scan(monkeypatch, "scan_ports", [ROUTER_HOST])
    assert main(["ports", ip]) == 1
    captured = capsys.readouterr()
    assert calls == {}
    assert phrase in captured.out
    assert "Fix:" in captured.out
    assert "Traceback" not in captured.out


def test_ports_says_when_nothing_answered(capsys, monkeypatch):
    _patch_port_scan(monkeypatch, "scan_ports", [])
    assert main(["ports", "192.168.1.9"]) == 1
    out = capsys.readouterr().out
    assert "No device answered at 192.168.1.9." in out
    assert "homenet devices" in out


def test_services_scans_one_host_and_shows_product_and_version(capsys, monkeypatch):
    host = Device(
        "192.168.1.1",
        None,
        None,
        "router.lan",
        [
            Port(22, "tcp", "open", "ssh", "Dropbear sshd", "2022.83"),
            Port(80, "tcp", "open", "http", "lighttpd", None),
            Port(443, "tcp", "closed", "https"),
        ],
    )
    calls = _patch_port_scan(monkeypatch, "scan_services", [host])
    assert main(["services", "192.168.1.1"]) == 0
    captured = capsys.readouterr()
    assert calls["target"] == "192.168.1.1"
    assert calls["kwargs"] == {"top_ports": 100}
    assert "allow_subnet" not in calls["kwargs"]
    assert captured.out == f"{BANNER}\n\n{format_services(host)}\n"
    assert "Dropbear sshd" in captured.out
    assert "2022.83" in captured.out
    assert "lighttpd" in captured.out
    assert "443" not in captured.out


def test_services_json_includes_product_and_version(capsys, monkeypatch):
    host = Device(
        "192.168.1.1",
        None,
        None,
        "router\x1b",
        [Port(22, "tcp", "open", "ssh", "Drop\x1bbear", "1\x1b.2")],
    )
    _patch_port_scan(monkeypatch, "scan_services", [host])
    assert main(["services", "192.168.1.1", "--json"]) == 0
    captured = capsys.readouterr()
    assert captured.out == format_services_json(host) + "\n"
    assert "\x1b" not in captured.out
    service = json.loads(captured.out)["services"][0]
    assert service["product"] == "Drop?bear"
    assert service["version"] == "1?.2"
    assert json.loads(captured.out)["hostname"] == "router?"


def test_services_help_has_no_subnet_option(capsys):
    with pytest.raises(SystemExit):
        main(["services", "--help"])
    out = capsys.readouterr().out
    assert "--subnet" not in out
    assert "allow_subnet" not in out


def test_services_does_not_scan_a_subnet(capsys, monkeypatch):
    calls = _patch_port_scan(monkeypatch, "scan_services", [ROUTER_HOST])
    assert main(["services", "192.168.1.0/24"]) == 1
    assert calls == {}
    assert "one device" in capsys.readouterr().out


def test_router_explains_plain_http_and_safe_steps(capsys, monkeypatch):
    result = RouterCheck(
        "192.168.1.1",
        [
            AdminPage("http://192.168.1.1/", 80, True, True, 200, "Router Login", "lighttpd"),
            AdminPage("https://192.168.1.1/", 443, True, False, 401, None, None),
            AdminPage("http://192.168.1.1:8080/", 8080, False, True, error="timed out"),
        ],
    )
    calls = {}

    def check(*args, **kwargs):
        calls["args"] = args
        calls["kwargs"] = kwargs
        return result

    monkeypatch.setattr(router, "check_router_admin", check)
    assert main(["router"]) == 0
    captured = capsys.readouterr()
    assert calls == {"args": (), "kwargs": {}}
    assert captured.out == f"{BANNER}\n\n{format_router(result)}\n"
    assert "not encrypted" in captured.out
    assert "Safe next steps" in captured.out
    assert "did not log in" in captured.out
    assert "Prefer the HTTPS address" in captured.out


def test_router_with_nothing_reachable_still_succeeds(capsys, monkeypatch):
    result = RouterCheck(
        "192.168.1.1",
        [AdminPage("http://192.168.1.1/", 80, False, True, error="connection refused")],
    )
    monkeypatch.setattr(router, "check_router_admin", lambda: result)
    assert main(["router"]) == 0
    out = capsys.readouterr().out
    assert "not reachable" in out
    assert "No admin page answered" in out
    assert "Do not guess passwords." in out


def test_router_json_error_uses_the_shared_shape(capsys, monkeypatch):
    def check():
        raise TargetNotAllowedError(
            "Could not detect your router (default gateway).",
            "Check you are connected (see `homenet whoami-net`).",
        )

    monkeypatch.setattr(router, "check_router_admin", check)
    assert main(["router", "--json"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    loaded = json.loads(captured.err)
    assert set(loaded) == {"error", "fix_hint"}
    assert "default gateway" in loaded["error"]
    assert loaded["fix_hint"]
    assert BANNER not in captured.err
    assert "Traceback" not in captured.err


def test_router_json_cleans_page_text(capsys, monkeypatch):
    result = RouterCheck(
        "192.168.1.1\x1b",
        [AdminPage("http://192.168.1.1/\x1b", 80, True, True, 200, "Hi\x1b", "ng\x1binx")],
    )
    monkeypatch.setattr(router, "check_router_admin", lambda: result)
    assert main(["router", "--json"]) == 0
    captured = capsys.readouterr()
    assert captured.out == format_router_json(result) + "\n"
    assert "\x1b" not in captured.out
    assert BANNER not in captured.out
    loaded = json.loads(captured.out)
    assert loaded["gateway"] == "192.168.1.1?"
    assert loaded["admin_reachable"] is True
    assert loaded["plain_http_reachable"] is True
    assert loaded["pages"][0]["title"] == "Hi?"


def test_speed_prints_numbers_and_no_banner(capsys, monkeypatch):
    result = SpeedResult(8.0, 1_000_000, 1.0, "https://speed.cloudflare.com/__down?bytes=1000000")
    calls = {}

    def measure(**kwargs):
        calls["kwargs"] = kwargs
        return result

    monkeypatch.setattr(speed, "measure_download", measure)
    assert main(["speed"]) == 0
    captured = capsys.readouterr()
    assert calls["kwargs"] == {}
    assert captured.out == format_speed(result) + "\n"
    assert BANNER not in captured.out
    assert "8.00 Mb/s" in captured.out
    assert captured.err == ""


def test_speed_json_and_error(capsys, monkeypatch):
    result = SpeedResult(8.0, 1000, 1.0, "https://example.test/\x1b")
    monkeypatch.setattr(speed, "measure_download", lambda **kwargs: result)
    assert main(["speed", "--json"]) == 0
    captured = capsys.readouterr()
    assert captured.out == format_speed_json(result) + "\n"
    assert json.loads(captured.out)["url"] == "https://example.test/?"
    assert "\x1b" not in captured.out

    def fail(**kwargs):
        raise SpeedError("Could not measure your internet speed.", "Check the internet.")

    monkeypatch.setattr(speed, "measure_download", fail)
    assert main(["speed", "--json"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert set(json.loads(captured.err)) == {"error", "fix_hint"}
    assert "Traceback" not in captured.err


def test_json_usage_error_prints_an_error_object(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["ports", "--json"])
    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    loaded = json.loads(captured.err)
    assert set(loaded) == {"error", "fix_hint"}
    assert "required" in loaded["error"]
    assert loaded["fix_hint"]
    assert "usage:" not in captured.err
    assert "Traceback" not in captured.err

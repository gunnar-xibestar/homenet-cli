"""CLI help text and doctor exit codes. Core checks are mocked."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from homenet.cli import BANNER, main
from homenet.core import baseline, checks, devices, netinfo
from homenet.core.baseline import BaselineError, BaselineNotFoundError, diff_devices
from homenet.core.checks import CheckResult
from homenet.core.netinfo import NetInfo, NetInfoError
from homenet.core.parser import Device, ParseError
from homenet.core.runner import NmapNotFoundError
from homenet.output import (
    format_device,
    format_device_json,
    format_devices,
    format_devices_json,
    format_diff,
    format_diff_json,
    format_doctor_json,
    format_error,
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


@pytest.mark.parametrize("command", ("router",))
def test_scan_stub_prints_banner_and_exits_nonzero(command, capsys):
    code = main([command])
    assert code == 1
    out = capsys.readouterr().out
    assert BANNER in out
    assert f"{command} is not implemented yet." in out


@pytest.mark.parametrize(
    ("command", "ip"),
    [("ports", "192.168.1.1"), ("services", "192.168.1.1")],
)
def test_ip_scan_stub_prints_banner_and_exits_nonzero(command, ip, capsys):
    code = main([command, ip])
    assert code == 1
    out = capsys.readouterr().out
    assert BANNER in out
    assert f"{command} is not implemented yet." in out


@pytest.mark.parametrize("command", ("device", "ports", "services"))
def test_ip_commands_require_an_address(command):
    with pytest.raises(SystemExit) as exc:
        main([command])
    assert exc.value.code != 0


def test_speed_stub_is_not_implemented(capsys):
    code = main(["speed"])
    assert code == 1
    out = capsys.readouterr().out
    assert "speed is not implemented yet." in out
    assert BANNER not in out


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
    ("whoami-net", "devices", "new-devices", "doctor"),
)
def test_json_flag_is_documented_on_the_commands_that_print_it(command, capsys):
    with pytest.raises(SystemExit) as exc:
        main([command, "--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "--json" in out
    assert "Errors go to stderr" in out


def test_device_help_offers_json(capsys):
    with pytest.raises(SystemExit):
        main(["device", "--help"])
    assert "--json" in capsys.readouterr().out


@pytest.mark.parametrize("command", ("baseline", "router", "speed", "ports", "services"))
def test_other_commands_have_no_json_flag(command, capsys):
    with pytest.raises(SystemExit):
        main([command, "--help"])
    assert "--json" not in capsys.readouterr().out


def test_new_devices_help_documents_exit_codes(capsys):
    with pytest.raises(SystemExit):
        main(["new-devices", "--help"])
    out = capsys.readouterr().out
    assert "Exit status is 0 when nothing changed" in out
    assert "also exits 1" in out


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


def test_devices_error_shows_a_hint_without_a_traceback(capsys, monkeypatch):
    _patch_detect(monkeypatch, HOME)
    _patch_sweep(
        monkeypatch,
        NmapNotFoundError("nmap is not installed.", "Try: sudo apt install nmap"),
    )
    assert main(["devices"]) == 1
    captured = capsys.readouterr()
    assert captured.out.startswith(BANNER + "\n")
    assert "nmap is not installed." in captured.out
    assert "Fix: Try: sudo apt install nmap" in captured.out
    assert "Traceback" not in captured.out
    assert "Traceback" not in captured.err
    assert "NmapNotFoundError" not in captured.out


def test_devices_json_error_goes_to_stderr(capsys, monkeypatch):
    _patch_detect(monkeypatch, HOME)
    _patch_sweep(monkeypatch, ParseError("nmap output was incomplete or corrupted.", "Try again."))
    assert main(["devices", "--json"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Fix: Try again." in captured.err
    assert BANNER not in captured.err
    assert "Traceback" not in captured.err
    assert "ParseError" not in captured.err


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


def test_device_scan_error_has_a_hint_and_no_traceback(capsys, monkeypatch):
    _patch_detect(monkeypatch, HOME)
    _patch_lookup(
        monkeypatch,
        NmapNotFoundError("nmap is not installed.", "Try: sudo apt install nmap"),
    )
    assert main(["device", "192.168.1.10"]) == 1
    captured = capsys.readouterr()
    assert "Fix: Try: sudo apt install nmap" in captured.out
    assert "Traceback" not in captured.out
    assert "NmapNotFoundError" not in captured.out


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


def test_baseline_save_error_has_a_hint_and_no_traceback(capsys, monkeypatch):
    _patch_detect(monkeypatch, HOME)
    _patch_sweep(monkeypatch, [LAPTOP])

    def save(found, path=None, now=None):
        raise BaselineError(
            "Could not save the baseline to /tmp/baseline.json: Permission denied",
            "Check that the folder is writable.",
        )

    monkeypatch.setattr(baseline, "save_baseline", save)
    assert main(["baseline"]) == 1
    captured = capsys.readouterr()
    assert "Could not save the baseline" in captured.out
    assert "Fix: Check that the folder is writable." in captured.out
    assert "Traceback" not in captured.out
    assert "BaselineError" not in captured.out


def test_new_devices_exits_0_when_nothing_changed(capsys, monkeypatch):
    _patch_detect(monkeypatch, HOME)
    _patch_sweep(monkeypatch, [LAPTOP])
    monkeypatch.setattr(baseline, "load_baseline", lambda: [LAPTOP])
    assert main(["new-devices"]) == 0
    captured = capsys.readouterr()
    report = diff_devices([LAPTOP], [LAPTOP])
    assert captured.out == f"{BANNER}\n\n{format_diff(report)}\n"
    assert "No changes since your saved snapshot." in captured.out
    assert captured.err == ""


def test_new_devices_exits_1_when_something_changed(capsys, monkeypatch):
    _patch_detect(monkeypatch, HOME)
    _patch_sweep(monkeypatch, [LAPTOP, PHONE])
    monkeypatch.setattr(baseline, "load_baseline", lambda: [LAPTOP])
    assert main(["new-devices"]) == 1
    captured = capsys.readouterr()
    report = diff_devices([LAPTOP], [LAPTOP, PHONE])
    assert captured.out == f"{BANNER}\n\n{format_diff(report)}\n"
    assert "New" in captured.out
    assert "phone" in captured.out
    assert captured.err == ""


def test_new_devices_json_exits_with_the_diff(capsys, monkeypatch):
    old = Device("192.168.1.5", "aa:aa:aa:aa:aa:aa", "Old", "printer")
    current = Device("192.168.1.5", "bb:bb:bb:bb:bb:bb", "New", "phone")
    _patch_detect(monkeypatch, HOME)
    _patch_sweep(monkeypatch, [current])
    monkeypatch.setattr(baseline, "load_baseline", lambda: [old])
    assert main(["new-devices", "--json"]) == 1
    captured = capsys.readouterr()
    report = diff_devices([old], [current])
    assert captured.out == format_diff_json(report) + "\n"
    assert captured.err == ""
    assert BANNER not in captured.out
    loaded = json.loads(captured.out)
    assert loaded["has_changes"] is True
    assert loaded["mac_changed"][0]["after"]["hostname"] == "phone"
    assert "spoof" not in captured.out


def test_new_devices_json_exits_0_when_nothing_changed(capsys, monkeypatch):
    _patch_detect(monkeypatch, HOME)
    _patch_sweep(monkeypatch, [LAPTOP])
    monkeypatch.setattr(baseline, "load_baseline", lambda: [LAPTOP])
    assert main(["new-devices", "--json"]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["has_changes"] is False
    assert BANNER not in captured.out
    assert captured.err == ""


def test_new_devices_missing_baseline_does_not_scan(capsys, monkeypatch):
    calls = _patch_sweep(monkeypatch, [LAPTOP])

    def load():
        raise BaselineNotFoundError("No baseline saved yet.", "Run `homenet baseline` first.")

    monkeypatch.setattr(baseline, "load_baseline", load)
    assert main(["new-devices"]) == 1
    captured = capsys.readouterr()
    assert calls == {}
    assert "No baseline saved yet." in captured.out
    assert "Fix: Run `homenet baseline` first." in captured.out
    assert "Traceback" not in captured.out
    assert "BaselineNotFoundError" not in captured.out


def test_new_devices_json_missing_baseline_goes_to_stderr(capsys, monkeypatch):
    def load():
        raise BaselineNotFoundError("No baseline saved yet.", "Run `homenet baseline` first.")

    monkeypatch.setattr(baseline, "load_baseline", load)
    assert main(["new-devices", "--json"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Fix: Run `homenet baseline` first." in captured.err
    assert BANNER not in captured.err
    assert "Traceback" not in captured.err


def test_whoami_json_prints_netinfo(capsys, monkeypatch):
    _patch_detect(monkeypatch, HOME)
    assert main(["whoami-net", "--json"]) == 0
    captured = capsys.readouterr()
    assert captured.out == format_whoami_json(HOME) + "\n"
    assert captured.err == ""
    assert BANNER not in captured.out
    assert "This computer" not in captured.out


def test_whoami_json_error_goes_to_stderr(capsys, monkeypatch):
    error = NetInfoError("No default route found.", "Connect to Wi-Fi or Ethernet and try again.")
    _patch_detect(monkeypatch, error)
    assert main(["whoami-net", "--json"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == format_error(str(error), error.hint) + "\n"
    assert "Traceback" not in captured.err


def test_doctor_json_exits_0_when_checks_pass(capsys, monkeypatch):
    results = [
        CheckResult("nmap", True, "nmap 7.95", severity="ok"),
        CheckResult("ip", True, "ip 6.1.0", severity="ok"),
    ]
    _patch_checks(monkeypatch, results)
    assert main(["doctor", "--json"]) == 0
    captured = capsys.readouterr()
    assert captured.out == format_doctor_json(results) + "\n"
    assert captured.err == ""
    assert json.loads(captured.out)["ok"] is True
    assert [item["name"] for item in json.loads(captured.out)["checks"]] == ["nmap", "ip"]


def test_doctor_json_exits_1_when_an_error_check_fails(capsys, monkeypatch):
    results = [
        CheckResult("nmap", False, "nmap is not installed", "sudo apt install nmap", "error"),
        CheckResult("privileges", False, "normal user", "Re-run with sudo", "warning"),
    ]
    _patch_checks(monkeypatch, results)
    assert main(["doctor", "--json"]) == 1
    captured = capsys.readouterr()
    assert captured.err == ""
    loaded = json.loads(captured.out)
    assert loaded["ok"] is False
    assert loaded["checks"][0]["fix_hint"] == "sudo apt install nmap"
    assert loaded["checks"][1]["severity"] == "warning"


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


def test_doctor_json_treats_warnings_as_success(capsys, monkeypatch):
    results = [CheckResult("privileges", False, "normal user", "Re-run with sudo", "warning")]
    _patch_checks(monkeypatch, results)
    assert main(["doctor", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["ok"] is True

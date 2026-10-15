"""CLI commands, exit codes and JSON output. Core is mocked; nothing real runs."""

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
    format_error_json,
    format_whoami,
    format_whoami_json,
)

ROOT = Path(__file__).resolve().parents[1]

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


def test_console_script_entry_point():
    data = _load_toml((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert data["project"]["scripts"]["homenet"] == "homenet.cli:main"
    dev = data["project"]["optional-dependencies"]["dev"]
    assert any(item.startswith("tomli") for item in dev)


@pytest.mark.parametrize(
    ("argv", "banner"),
    [
        (["router"], True),
        (["ports", "192.168.1.1"], True),
        (["services", "192.168.1.1"], True),
        (["speed"], False),
    ],
    ids=["router", "ports", "services", "speed"],
)
def test_stub_commands_are_not_implemented(argv, banner, capsys):
    assert main(argv) == 1
    out = capsys.readouterr().out
    assert f"{argv[0]} is not implemented yet." in out
    assert (BANNER in out) is banner


@pytest.mark.parametrize("argv", [[], ["device"], ["ports"], ["services"]])
def test_usage_errors_exit_nonzero(argv):
    with pytest.raises(SystemExit) as exc:
        main(argv)
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
            ["WARN  privileges", "setcap cap_net_raw+eip", "No errors. 1 warning."],
            ["FAIL", "$(which nmap)"],
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

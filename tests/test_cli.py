"""CLI help text and doctor exit codes. Core checks are mocked."""

from __future__ import annotations

from pathlib import Path

import pytest
import tomllib

from homenet.cli import BANNER, main
from homenet.core import checks
from homenet.core.checks import CheckResult

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
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert data["project"]["scripts"]["homenet"] == "homenet.cli:main"


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


@pytest.mark.parametrize("command", ("whoami-net", "devices", "router", "baseline", "new-devices"))
def test_scan_stub_prints_banner_and_exits_nonzero(command, capsys):
    code = main([command])
    assert code == 1
    out = capsys.readouterr().out
    assert BANNER in out
    assert f"{command} is not implemented yet." in out


@pytest.mark.parametrize(
    ("command", "ip"),
    [("device", "192.168.1.20"), ("ports", "192.168.1.1"), ("services", "192.168.1.1")],
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
    source = (
        Path(checks.__file__).resolve().parent.parent.joinpath("cli.py").read_text(encoding="utf-8")
    )
    assert "subprocess" not in source
    assert "os.system" not in source
    assert "Popen" not in source


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
                "Re-run with sudo, or sudo setcap cap_net_raw+ep $(which nmap)",
            ),
            CheckResult("network", True, "default route via 192.168.1.1, interface eth0 (up)"),
        ],
    )
    assert main(["doctor"]) == 1
    out = capsys.readouterr().out
    assert "FAIL  nmap" in out
    assert "PASS  ip" in out
    assert "Fix: sudo apt install nmap" in out
    assert "setcap cap_net_raw+ep" in out
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
                "Re-run with sudo, or sudo setcap cap_net_raw+ep $(which nmap)",
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
    assert "Fix: Re-run with sudo" in out
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

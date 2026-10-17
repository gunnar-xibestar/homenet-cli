"""--show-cmd and explain. Core is mocked; nothing real runs."""

from __future__ import annotations

import json

import pytest

from homenet.cli import BANNER, main
from homenet.core import baseline, checks, devices, dns, netinfo, ports, router, speed, wifi
from homenet.core.checks import CheckResult
from homenet.core.commands import Command, notify
from homenet.core.dns import DnsConfig, DnsServer, LookupResult
from homenet.core.netinfo import NetInfo, NetInfoError
from homenet.core.parser import Device, Port
from homenet.core.router import RouterCheck
from homenet.core.runner import NmapNotFoundError
from homenet.core.speed import SpeedResult
from homenet.core.wifi import WifiInfo
from homenet.output import format_devices_json

HOME = NetInfo("eth0", "192.168.1.100", "192.168.1.1", "192.168.1.0/24")
NET = "192.168.1.0/24"
LAPTOP = Device("192.168.1.10", "AA:BB:CC:DD:EE:10", "Dell", "laptop")
PORT_HOST = Device("192.168.1.1", None, None, "router", [Port(80, "tcp", "open", "http")])
EXEC = Command(("nmap", "-sn", NET), "find devices that are up (ping sweep)")
HTTP = Command(
    ("https://speed.cloudflare.com/__down?bytes=1000000",),
    "download 1000000 bytes to estimate speed",
    "http",
    20,
)
PLANNED = (EXEC, HTTP)
_LOOKUP = LookupResult("example.com", True, ("93.184.216.34",), 10.0)
_INVALID_HINT = "Use an IP address or subnet like 192.168.1.0/24."

# command, argv, prints the safety banner, accepts --json
_SHOW = (
    ("whoami-net", ["whoami-net"], False, True),
    ("devices", ["devices"], True, True),
    ("device", ["device", "192.168.1.10"], True, True),
    ("ports", ["ports", "192.168.1.1"], True, True),
    ("services", ["services", "192.168.1.1"], True, True),
    ("router", ["router"], True, True),
    ("baseline", ["baseline"], True, False),
    ("new-devices", ["new-devices"], True, True),
    ("speed", ["speed"], False, True),
    ("wifi", ["wifi"], False, True),
    ("dns", ["dns"], False, True),
    ("doctor", ["doctor"], False, True),
)
# command, extra argv, kwargs passed to planned_commands
_EXPLAIN = (
    ("whoami-net", [], {}),
    ("doctor", [], {}),
    ("speed", [], {}),
    ("wifi", [], {}),
    ("dns", [], {}),
    ("devices", [], {"local_network": NET}),
    ("baseline", [], {"local_network": NET}),
    ("new-devices", [], {"local_network": NET}),
    ("device", ["192.168.1.10"], {"local_network": NET}),
    ("ports", ["192.168.1.1"], {"target": "192.168.1.1", "local_network": NET, "top_ports": 100}),
    (
        "services",
        ["192.168.1.1"],
        {"target": "192.168.1.1", "local_network": NET, "top_ports": 100, "allow_subnet": False},
    ),
    ("router", [], {"gateway": "192.168.1.1", "local_network": NET}),
)


# json mode is shared code; two commands (one with and one without the banner) cover it.
_SHOW_JSON = {"devices", "doctor"}


def _show_params():
    for command, argv, banner, has_json in _SHOW:
        yield pytest.param(command, argv, banner, False, id=command)
        if has_json and command in _SHOW_JSON:
            yield pytest.param(command, argv, banner, True, id=f"{command}-json")


def _sample(command: str) -> Command:
    return HTTP if command in ("router", "speed") else EXEC


def _result(command: str):
    if command in ("devices", "baseline", "new-devices"):
        return [LAPTOP]
    if command == "device":
        return LAPTOP
    if command in ("ports", "services"):
        return [PORT_HOST]
    if command == "router":
        return RouterCheck("192.168.1.1")
    if command == "speed":
        return SpeedResult(8.0, 1_000_000, 1.0, HTTP.url)
    if command == "wifi":
        return WifiInfo(True, interface="wlan0", ssid="Home", signal_dbm=-55)
    if command == "dns":
        return DnsConfig([DnsServer("192.168.1.1", "resolvectl")], "resolvectl")
    return [CheckResult("nmap", True, "nmap 7.95", severity="ok")]


def _patch_run(monkeypatch, command: str, cmd: Command) -> dict:
    calls = {"n": 0}

    def hit() -> None:
        calls["n"] += 1
        notify(cmd)

    def detect() -> NetInfo:
        if command == "whoami-net":
            hit()
        return HOME

    def run(*_args, **_kwargs):
        hit()
        return _result(command)

    monkeypatch.setattr(netinfo, "detect", detect)
    targets = {
        "devices": (devices, "sweep"),
        "device": (devices, "get_device"),
        "baseline": (devices, "sweep"),
        "new-devices": (devices, "sweep"),
        "ports": (ports, "scan_ports"),
        "services": (ports, "scan_services"),
        "router": (router, "check_router_admin"),
        "speed": (speed, "measure_download"),
        "doctor": (checks, "run_all_checks"),
    }
    if command in targets:
        mod, name = targets[command]
        monkeypatch.setattr(mod, name, run)
    if command == "doctor":
        monkeypatch.setattr(checks, "OPTIONAL_TOOLS", ())
    if command == "wifi":
        monkeypatch.setattr(wifi, "get_wifi_info", run)
    if command == "dns":
        monkeypatch.setattr(dns, "get_dns_servers", run)
        monkeypatch.setattr(dns, "dns_lookup_test", lambda *_a, **_k: _LOOKUP)
    if command == "baseline":
        monkeypatch.setattr(baseline, "save_baseline", lambda *_a, **_k: "baseline.json")
    if command == "new-devices":
        monkeypatch.setattr(baseline, "load_baseline", lambda path=None: [LAPTOP])
    return calls


def _payload(cmd: Command) -> dict:
    data = cmd.to_dict()
    return data


@pytest.fixture
def no_scans(monkeypatch):
    """Fail if explain (or a test) actually scans, fetches, or detects."""

    def fail(*_args, **_kwargs):
        raise AssertionError("explain must not run a scan")

    monkeypatch.setattr(netinfo, "detect", fail)
    monkeypatch.setattr(devices, "sweep", fail)
    monkeypatch.setattr(devices, "get_device", fail)
    monkeypatch.setattr(ports, "scan_ports", fail)
    monkeypatch.setattr(ports, "scan_services", fail)
    monkeypatch.setattr(router, "check_router_admin", fail)
    monkeypatch.setattr(speed, "measure_download", fail)
    monkeypatch.setattr(wifi, "get_wifi_info", fail)
    monkeypatch.setattr(dns, "get_dns_servers", fail)
    monkeypatch.setattr(dns, "dns_lookup_test", fail)
    monkeypatch.setattr(checks, "run_all_checks", fail)
    monkeypatch.setattr(baseline, "save_baseline", fail)
    monkeypatch.setattr(baseline, "load_baseline", fail)


@pytest.mark.parametrize(("command", "argv", "banner", "json_mode"), list(_show_params()))
def test_show_cmd(command, argv, banner, json_mode, capsys, monkeypatch):
    cmd = _sample(command)
    calls = _patch_run(monkeypatch, command, cmd)
    full = [*argv, "--json"] if json_mode else list(argv)
    assert main([*full, "--show-cmd"]) == 0
    captured = capsys.readouterr()
    assert calls["n"] == 1
    assert "\x1b" not in captured.out + captured.err
    assert (BANNER in captured.out) is (banner and not json_mode)
    if json_mode:
        assert captured.err == ""
        assert "$" not in captured.err
        loaded = json.loads(captured.out)
        assert loaded["commands"] == [_payload(cmd)]
        assert set(loaded["commands"][0]) == {"argv", "display", "purpose", "kind"}
    else:
        assert captured.err == f"$ {cmd.display()}\n"
        assert "commands" not in captured.out


def test_show_cmd_before_the_command_is_honoured(capsys, monkeypatch):
    calls = _patch_run(monkeypatch, "devices", EXEC)
    assert main(["--show-cmd", "devices"]) == 0
    captured = capsys.readouterr()
    assert calls["n"] == 1
    assert captured.err == f"$ {EXEC.display()}\n"
    assert BANNER in captured.out


def test_show_cmd_json_keeps_the_rest_of_the_document(capsys, monkeypatch):
    _patch_run(monkeypatch, "devices", EXEC)
    assert main(["devices", "--show-cmd", "--json"]) == 0
    loaded = json.loads(capsys.readouterr().out)
    commands = loaded.pop("commands")
    assert commands == [EXEC.to_dict()]
    assert loaded == json.loads(format_devices_json([LAPTOP]))


def test_show_cmd_cleans_the_displayed_line(capsys, monkeypatch):
    nasty = Command(("nmap", "-sn", "192.168.1.0/24\x1b[2J"), "find\x1b devices")
    _patch_run(monkeypatch, "devices", nasty)
    assert main(["devices", "--show-cmd"]) == 0
    err = capsys.readouterr().err
    assert err.startswith("$ ") and "\x1b" not in err and "?" in err
    assert main(["devices", "--show-cmd", "--json"]) == 0
    captured = capsys.readouterr()
    assert captured.err == "" and "\x1b" not in captured.out
    item = json.loads(captured.out)["commands"][0]
    assert "\x1b" not in item["display"] and "\x1b" not in item["purpose"]
    assert "\x1b" in item["argv"][2]


def test_show_cmd_json_error_lists_commands_and_skips_the_dollar_line(capsys, monkeypatch):
    def sweep(*_args, **_kwargs):
        notify(EXEC)
        raise NmapNotFoundError("nmap is not installed.", "Try: sudo apt install nmap")

    monkeypatch.setattr(netinfo, "detect", lambda: HOME)
    monkeypatch.setattr(devices, "sweep", sweep)
    assert main(["devices", "--show-cmd", "--json"]) == 1
    captured = capsys.readouterr()
    assert captured.out == "" and "$" not in captured.err and "Traceback" not in captured.err
    loaded = json.loads(captured.err)
    assert set(loaded) == {"commands", "error", "fix_hint"}
    assert loaded["commands"] == [EXEC.to_dict()]
    assert loaded["fix_hint"] == "Try: sudo apt install nmap"
    notify(EXEC)
    assert capsys.readouterr().err == ""


def _explain_params():
    # devices, baseline and new-devices share plan_scan; keep one of them.
    for command, extra, params in _EXPLAIN:
        if command not in ("baseline", "new-devices"):
            yield pytest.param(command, extra, params, False, id=command)
        if command in ("devices", "router"):
            yield pytest.param(command, extra, params, True, id=f"{command}-json")


@pytest.mark.parametrize(("command", "extra", "params", "json_mode"), list(_explain_params()))
def test_explain(command, extra, params, json_mode, capsys, monkeypatch, no_scans):
    seen = {}

    def fake(name, **kwargs):
        seen["name"] = name
        seen["kwargs"] = kwargs
        return list(PLANNED)

    monkeypatch.setattr("homenet.cli.planned_commands", fake)
    if params:
        monkeypatch.setattr(netinfo, "detect", lambda: HOME)
    argv = ["explain", command, *extra]
    assert main([*argv, "--json"] if json_mode else argv) == 0
    captured = capsys.readouterr()
    assert seen == {"name": command, "kwargs": params}
    assert captured.err == "" and BANNER not in captured.out and "\x1b" not in captured.out
    if json_mode:
        loaded = json.loads(captured.out)
        assert set(loaded) == {"command", "commands"}
        assert loaded["command"] == command
        assert loaded["commands"] == [cmd.to_dict() for cmd in PLANNED]
    else:
        blocks = [f"$ {cmd.display()}\n  {cmd.purpose}" for cmd in PLANNED]
        assert captured.out == "·\n" * 2 + "\n\n".join(blocks) + "\n" + "·\n" * 5


@pytest.mark.parametrize(
    ("argv", "params", "code"),
    [
        (["explain", "devices", "--network", NET], {"local_network": NET}, 0),
        (
            ["explain", "ports", "192.168.1.1", "--network", NET],
            {"target": "192.168.1.1", "local_network": NET, "top_ports": 100},
            0,
        ),
        (
            ["explain", "router", "--network", NET, "--gateway", "192.168.1.1"],
            {"gateway": "192.168.1.1", "local_network": NET},
            0,
        ),
        (["explain", "devices", "--network", "nope"], None, 1),
        (["explain", "new-devices", "--network", "fe80::/64"], None, 2),
    ],
)
def test_explain_network_skips_ip_and_rejects_a_bad_cidr(
    argv, params, code, capsys, monkeypatch, no_scans
):
    seen = {}

    def fake(name, **kwargs):
        seen["name"] = name
        seen["kwargs"] = kwargs
        return [EXEC]

    monkeypatch.setattr("homenet.cli.planned_commands", fake)
    assert main(argv) == code
    captured = capsys.readouterr()
    assert "Traceback" not in captured.out + captured.err
    if params is None:
        assert seen == {}
        assert "not a valid" in captured.out and _INVALID_HINT in captured.out
        assert "Fix:" in captured.out and "ValueError" not in captured.out
        return
    assert seen == {"name": argv[1], "kwargs": params}
    assert f"$ {EXEC.display()}" in captured.out


def test_explain_cleans_displayed_commands(capsys, monkeypatch, no_scans):
    nasty = Command(("nmap", "-sn", "192.168.1.0/24\x1b[2J"), "find\x1b devices")
    monkeypatch.setattr("homenet.cli.planned_commands", lambda *_a, **_k: [nasty])
    assert main(["explain", "speed"]) == 0
    out = capsys.readouterr().out
    assert (
        out.startswith("·\n" * 2 + "$ ")
        and "\x1b" not in out
        and "?" in out
        and "find? devices" in out
    )
    assert main(["explain", "doctor", "--json"]) == 0
    item = json.loads(capsys.readouterr().out)["commands"][0]
    assert "\x1b" not in item["display"] and "\x1b" not in item["purpose"]
    assert "\x1b" in item["argv"][2]


@pytest.mark.parametrize(
    ("command", "code", "json_mode"),
    [("devices", 1, False), ("devices", 1, True), ("new-devices", 2, False), ("ports", 1, False)],
)
def test_explain_planner_valueerror_is_a_friendly_target_error(
    command, code, json_mode, capsys, monkeypatch, no_scans
):
    monkeypatch.setattr(netinfo, "detect", lambda: HOME)
    monkeypatch.setattr(
        "homenet.cli.planned_commands", lambda *_a, **_k: (_ for _ in ()).throw(ValueError("bad"))
    )
    argv = ["explain", command]
    if command == "ports":
        argv.append("192.168.1.9")
    assert main([*argv, "--json"] if json_mode else argv) == code
    captured = capsys.readouterr()
    blob = captured.err if json_mode else captured.out
    assert "Traceback" not in captured.out + captured.err
    assert "ValueError" not in captured.out + captured.err
    assert "not a valid" in blob and _INVALID_HINT in blob
    if command == "ports":
        assert "192.168.1.9" in blob
    if json_mode:
        assert captured.out == ""
        assert set(json.loads(blob)) == {"error", "fix_hint"}
    else:
        assert "Fix:" in blob and BANNER not in blob


@pytest.mark.parametrize(
    ("command", "code", "json_mode"),
    [("devices", 1, False), ("router", 1, True), ("new-devices", 2, False)],
)
def test_explain_detection_failure_uses_the_fix_hint(
    command, code, json_mode, capsys, monkeypatch, no_scans
):
    def detect() -> NetInfo:
        raise NetInfoError(
            "Could not detect your home network.",
            "Connect to Wi-Fi or Ethernet, then try `homenet whoami-net`.",
        )

    def fail(*_args, **_kwargs):
        raise AssertionError("planned")

    monkeypatch.setattr(netinfo, "detect", detect)
    monkeypatch.setattr("homenet.cli.planned_commands", fail)
    argv = ["explain", command, "--json"] if json_mode else ["explain", command]
    assert main(argv) == code
    captured = capsys.readouterr()
    blob = captured.err if json_mode else captured.out
    assert "Could not detect your home network." in blob
    assert "homenet whoami-net" in blob
    assert "Traceback" not in captured.out + captured.err
    assert "NetInfoError" not in blob
    if json_mode:
        assert captured.out == ""
        assert json.loads(blob)["fix_hint"]
    else:
        assert blob.startswith("Could not detect") and "Fix:" in blob and BANNER not in blob


@pytest.mark.parametrize(
    ("argv", "json_mode"),
    [
        (["device", "nope"], False),
        (["ports", "192.168.1.0/24"], False),
        (["services", "2001:db8::1"], False),
        (["device", "nope"], True),
    ],
)
def test_explain_bad_address_matches_the_real_command(argv, json_mode, capsys, no_scans):
    real_argv = [*argv, "--json"] if json_mode else argv
    assert main(real_argv) == 1
    real = capsys.readouterr()
    assert main(["explain", *real_argv]) == 1
    explained = capsys.readouterr()
    assert "Traceback" not in explained.out + explained.err
    if json_mode:
        assert explained.out == "" and explained.err == real.err
        assert set(json.loads(explained.err)) == {"error", "fix_hint"}
    else:
        assert real.out == f"{BANNER}\n\n{explained.out}"
        assert "Fix:" in explained.out and BANNER not in explained.out


@pytest.mark.parametrize(
    ("argv", "code"),
    [
        (["explain"], 2),
        (["explain", "nope"], 2),
        (["explain", "ports"], 2),
        (["explain", "speed", "1.2.3.4"], 2),
    ],
)
def test_explain_usage_errors(argv, code, capsys, no_scans):
    if argv in (["explain"], ["explain", "nope"]):
        with pytest.raises(SystemExit) as exc:
            main(argv)
        assert exc.value.code == code
    else:
        assert main(argv) == code
    captured = capsys.readouterr()
    assert "Traceback" not in captured.out + captured.err

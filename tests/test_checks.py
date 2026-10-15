import dataclasses
import json
import re
import socket
import struct

import pytest

from homenet.cli import build_parser
from homenet.core.checks import (
    CheckResult,
    check_network,
    check_ping,
    check_privileges,
    check_tool,
    check_wsl,
    resolve_homenet_program,
    run_all_checks,
)
from homenet.output import format_doctor_json

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


@pytest.mark.parametrize(
    ("argv0", "found", "files", "expected"),
    [
        (
            "/opt/venv/bin/homenet",
            "/usr/bin/homenet",
            {"/opt/venv/bin/homenet"},
            "/opt/venv/bin/homenet",
        ),
        (
            "/usr/bin/pytest",
            "/opt/pipx/bin/homenet",
            {"/opt/pipx/bin/homenet"},
            "/opt/pipx/bin/homenet",
        ),
        ("/usr/bin/pytest", None, set(), None),
        ("homenet", None, set(), None),
        ("", None, set(), None),
    ],
)
def test_resolve_homenet_program(argv0, found, files, expected):
    got = resolve_homenet_program(
        argv0=argv0,
        which=lambda name: found if name == "homenet" else None,
        is_file=files.__contains__,
    )
    assert got == expected


def test_resolve_homenet_program_prefers_the_running_script(tmp_path, monkeypatch):
    script = tmp_path / "homenet"
    script.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    assert resolve_homenet_program(argv0="homenet", which=lambda _name: "/other/homenet") == str(
        script.resolve()
    )


@pytest.mark.parametrize(
    ("argv0", "found", "snippet"),
    [
        ("/opt/venv/bin/homenet", None, "sudo /opt/venv/bin/homenet devices"),
        (
            "/usr/bin/pytest",
            "/home/ada/.local/bin/homenet",
            "sudo /home/ada/.local/bin/homenet devices",
        ),
        ("pytest", None, 'sudo "$(command -v homenet)" devices'),
    ],
)
def test_privileges_unprivileged_is_warning(argv0, found, snippet):
    files = {"/opt/venv/bin/homenet", "/home/ada/.local/bin/homenet"}
    r = check_privileges(
        geteuid=lambda: 1000,
        read_text=lambda p: "CapEff:\t0\n",
        environ={},
        argv0=argv0,
        which=lambda name: found if name == "homenet" else None,
        is_file=files.__contains__,
    )
    assert not r.ok and r.severity == "warning"
    assert snippet in (r.fix_hint or "")
    assert "homenet doctor does not need sudo" in (r.fix_hint or "")
    assert "sudo homenet doctor" not in (r.fix_hint or "")
    assert "setcap" not in (r.fix_hint or "")
    named = re.search(r"`sudo .* ([a-z0-9-]+)`", r.fix_hint or "")
    assert named is not None and named.group(1) != "doctor"
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


_ANY = "0.0.0.0"  # noqa: S104 - default route and unspecified gateway in /proc/net/route


def _le_hex(ip: str) -> str:
    packed = struct.pack("<L", struct.unpack(">I", socket.inet_aton(ip))[0])
    return packed.hex()


def _proc_route(*rows: tuple[str, str, str, str]) -> str:
    """Build /proc/net/route text. Each row is iface, destination, gateway, mask."""
    lines = ["Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask"]
    for iface, dest, gateway, mask in rows:
        lines.append(
            f"{iface}\t{_le_hex(dest)}\t{_le_hex(gateway)}\t0003\t0\t0\t0\t{_le_hex(mask)}"
        )
    return "\n".join(lines) + "\n"


WSL_ROUTE = _proc_route(
    ("eth0", _ANY, "172.22.240.1", _ANY),
    ("eth0", "172.22.240.0", _ANY, "255.255.240.0"),
)
HOME_ROUTE = _proc_route(
    ("wlp2s0", _ANY, "192.168.1.1", _ANY),
    ("wlp2s0", "192.168.1.0", _ANY, "255.255.255.0"),
)


@pytest.mark.parametrize(
    ("env", "version", "route", "expect"),
    [
        ({"WSL_DISTRO_NAME": "Ubuntu"}, None, WSL_ROUTE, True),
        ({}, "Linux version 5.15.90.1-microsoft-standard-WSL2", WSL_ROUTE, True),
        ({}, "Linux version 5.15.90.1-MICROSOFT-standard", WSL_ROUTE, True),
        ({}, "Linux version 6.12", WSL_ROUTE, False),
        ({"WSL_DISTRO_NAME": "Ubuntu"}, None, HOME_ROUTE, False),
        ({"WSL_DISTRO_NAME": "   "}, "Linux version 6.12", WSL_ROUTE, False),
        ({}, None, WSL_ROUTE, False),
    ],
    ids=["env", "proc-version", "case", "not-wsl", "mirrored", "blank-env", "no-version"],
)
def test_wsl_nat_check(env, version, route, expect):
    def read(path):
        if path == "/proc/net/route":
            return route
        if path == "/proc/version":
            if version is None:
                raise OSError(path)
            return version
        raise AssertionError(path)

    result = check_wsl(read_text=read, environ=env)
    if not expect:
        assert result is None
        return
    assert result is not None
    assert result.name == "wsl" and not result.ok and result.severity == "warning"
    assert "WSL virtual network" in result.detail and "home LAN" in result.detail
    assert "172.22.240.0/20" in result.detail
    assert "networkingMode=mirrored" in (result.fix_hint or "")
    assert "[wsl2]" in (result.fix_hint or "")
    assert "%UserProfile%" in (result.fix_hint or "")
    assert "wsl --shutdown" in (result.fix_hint or "")


def test_run_all_checks_wsl_nat_is_a_warning(load_fixture):
    files = {
        "/proc/net/route": WSL_ROUTE,
        "/sys/class/net/eth0/operstate": "up\n",
        "/proc/self/status": "CapEff:\t0000000000000000\n",
    }

    def read(path):
        if path not in files:
            raise AssertionError(path)
        return files[path]

    results = run_all_checks(
        which=lambda n: f"/usr/bin/{n}",
        run=_runner(load_fixture),
        geteuid=lambda: 1000,
        read_text=read,
        environ={"WSL_DISTRO_NAME": "Ubuntu"},
        argv0="/opt/venv/bin/homenet",
        is_file=lambda path: path == "/opt/venv/bin/homenet",
    )
    assert [r.name for r in results] == ["nmap", "ip", "privileges", "network", "ping", "wsl"]
    assert results[-1].severity == "warning"
    assert not any(not r.ok and r.severity != "warning" for r in results)
    loaded = json.loads(format_doctor_json(results))
    assert loaded["ok"] is True
    assert loaded["checks"][-1]["name"] == "wsl"
    assert loaded["checks"][-1]["severity"] == "warning"
    assert "networkingMode=mirrored" in loaded["checks"][-1]["fix_hint"]

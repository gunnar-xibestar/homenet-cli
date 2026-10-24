"""homenet ports --local. Raw ss text fixtures; the runner is mocked."""

from __future__ import annotations

import json
import subprocess

import pytest

from homenet.cli import main
from homenet.core import local_ports
from homenet.core.local_ports import Listener, _parse_ss

HEADER = "State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"


def _ok(stdout: str = HEADER, returncode: int = 0, stderr: str = ""):
    def run(cmd):
        return subprocess.CompletedProcess(list(cmd.argv), returncode, stdout, stderr)

    return run


@pytest.fixture
def fake_ss(monkeypatch):
    """Point build_local_ports_commands at a fake ss and let a test choose the runner."""
    monkeypatch.setattr(local_ports.shutil, "which", lambda name: "/usr/bin/ss")

    def use(run):
        real = local_ports.scan_local_ports
        monkeypatch.setattr(
            local_ports, "scan_local_ports", lambda **kw: real(run=run, ss_path="/usr/bin/ss")
        )

    return use


@pytest.mark.parametrize(
    ("line", "protocol", "expected"),
    [
        (
            'LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=812,fd=3))',
            "tcp",
            [Listener("tcp", "0.0.0.0", 22, "sshd", 812)],  # noqa: S104
        ),
        ("LISTEN 0 128 127.0.0.1:631 0.0.0.0:*", "tcp", [Listener("tcp", "127.0.0.1", 631)]),
        (
            'LISTEN 0 4096 [::]:80 [::]:* users:(("nginx",pid=9,fd=6),("nginx",pid=10,fd=6))',
            "tcp",
            [Listener("tcp", "::", 80, "nginx", 9)],
        ),
        ("LISTEN 0 128 [::1]:5432 [::]:*", "tcp", [Listener("tcp", "::1", 5432)]),
        ("UNCONN 0 0 *:5353 *:*", "udp", [Listener("udp", "*", 5353)]),
        (
            'UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=600,fd=13))',
            "udp",
            [Listener("udp", "127.0.0.53%lo", 53, "systemd-resolve", 600)],
        ),
    ],
)
def test_parse_ss_lines(line, protocol, expected):
    assert _parse_ss(HEADER + line + "\n", protocol) == expected


@pytest.mark.parametrize("text", ["", HEADER, "garbage\nnot ss output at all\n:::\n", "\x00\xff"])
def test_parse_ss_garbage_gives_no_listeners(text):
    assert _parse_ss(text, "tcp") == []


def test_escape_in_process_name_is_cleaned():
    line = 'LISTEN 0 1 0.0.0.0:8080 0.0.0.0:* users:(("ev\x1b[31mil\x07",pid=1,fd=3))'
    (item,) = _parse_ss(HEADER + line + "\n", "tcp")
    assert "\x1b" not in item.process and "\x07" not in item.process


def _run_raising(exc):
    def run(cmd):
        raise exc

    return run


@pytest.mark.parametrize(
    "run",
    [
        _ok(returncode=1, stderr="Cannot open netlink socket"),
        _run_raising(subprocess.TimeoutExpired(["ss"], 5)),
        _run_raising(FileNotFoundError(2, "No such file", "ss")),
    ],
    ids=["nonzero", "timeout", "vanished"],
)
def test_ss_failures_are_friendly(run, fake_ss, capsys):
    fake_ss(run)
    assert main(["ports", "--local"]) == 1
    captured = capsys.readouterr()
    assert "Fix:" in captured.out + captured.err
    assert "Traceback" not in captured.out + captured.err


def test_ss_missing_gives_install_hint(monkeypatch, capsys):
    monkeypatch.setattr(local_ports.shutil, "which", lambda name: None)
    assert main(["ports", "--local"]) == 1
    assert "iproute2" in capsys.readouterr().out


@pytest.mark.parametrize(
    "argv",
    [
        ["ports"],
        ["ports", "--local", "192.168.1.1"],
        *(
            pytest.param(
                argv,
                marks=pytest.mark.xfail(
                    strict=True, raises=TypeError, reason="_fail_message() called without hint"
                ),
            )
            for argv in (
                ["explain", "ports", "192.168.1.1", "--local"],
                ["explain", "devices", "--local"],
            )
        ),
    ],
)
def test_bad_local_usage_exits_2(argv, monkeypatch):
    monkeypatch.setattr(local_ports.shutil, "which", lambda name: "/usr/bin/ss")
    assert main(argv) == 2


def test_ports_local_happy_path(fake_ss, capsys):
    tcp = HEADER + 'LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=812,fd=3))\n'
    fake_ss(lambda cmd: _ok(tcp if "-ltnp" in cmd.argv else HEADER)(cmd))
    assert main(["ports", "--local", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["listeners"] == [
        {"protocol": "tcp", "address": "0.0.0.0", "port": 22, "process": "sshd", "pid": 812}  # noqa: S104
    ]


def test_explain_ports_local_lists_both_ss_commands(monkeypatch, capsys):
    monkeypatch.setattr(local_ports.shutil, "which", lambda name: "/usr/bin/ss")
    assert main(["explain", "ports", "--local", "--json"]) == 0
    out = capsys.readouterr().out
    assert "-ltnp" in out and "-lunp" in out


@pytest.mark.xfail(strict=True, reason="explain ports --local does not catch LocalPortsError")
def test_explain_ports_local_without_ss_is_friendly(monkeypatch, capsys):
    monkeypatch.setattr(local_ports.shutil, "which", lambda name: None)
    assert main(["explain", "ports", "--local"]) == 1

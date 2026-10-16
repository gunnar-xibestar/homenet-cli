"""Status line and -v/-vv. Core is mocked; nothing real runs.

One case per behavior: terminal on/off, --json, -v, -vv, the line clearing,
and the speed progress callback (warmup, then megabits, cleared on a TTY).
"""

from __future__ import annotations

import re
import sys
import threading
import time

import pytest

from homenet.cli import BANNER, main
from homenet.core import baseline, devices, netinfo, speed
from homenet.core.baseline import DeviceDiff
from homenet.core.netinfo import NetInfo
from homenet.core.parser import Device
from homenet.core.speed import SpeedResult
from homenet.output import format_devices, format_devices_json, format_speed, format_speed_json

NET = "192.168.1.0/24"
HOME = NetInfo("eth0", "192.168.1.100", "192.168.1.1", NET)
DEVICE = Device("192.168.1.10", "AA:BB:CC:DD:EE:10", "Dell", "laptop")
_STEPS = "Running nmap…\nParsed 7 hosts\nResolving names…\n"
_PROGRESS = "About 50% done?[K\n"


class _Err:
    def __init__(self, tty: bool) -> None:
        self._tty = tty
        self._parts: list[str] = []
        self._lock = threading.Lock()

    def write(self, data: str) -> int:
        with self._lock:
            self._parts.append(data)
        return len(data)

    def flush(self) -> None:
        return None

    def isatty(self) -> bool:
        return self._tty

    def getvalue(self) -> str:
        with self._lock:
            return "".join(self._parts)


def _visible_tail(text: str) -> str:
    line = ""
    for char in text.split("\n")[-1]:
        line = "" if char == "\r" else line + char
    return line.strip()


@pytest.mark.parametrize(
    ("argv", "tty", "mode"),
    [
        (["devices"], False, "quiet"),
        (["devices"], True, "spinner"),
        (["devices", "--json"], True, "json"),
        (["-v", "devices"], False, "steps"),
        (["devices", "-vv"], False, "stats"),
        (["devices", "-vv"], True, "both"),
    ],
)
def test_devices_progress(argv, tty, mode, monkeypatch, capsys):
    err = _Err(tty)
    monkeypatch.setattr(sys, "stderr", err)
    seen: dict = {}

    def sweep(target=None, **kwargs):
        seen["kwargs"] = kwargs
        if mode in ("spinner", "both"):
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline and "\r" not in err.getvalue():
                time.sleep(0.01)
            assert "\r" in err.getvalue()
        step = kwargs.get("on_step")
        if step is not None:
            step("Running nmap…")
            step("Parsed 7 hosts")
            step("Resolving names…")
        progress = kwargs.get("on_progress")
        if progress is not None:
            progress("About 50% done\x1b[K")
        return [DEVICE]

    monkeypatch.setattr(netinfo, "detect", lambda: HOME)
    monkeypatch.setattr(devices, "sweep", sweep)
    assert main(argv) == 0
    out = capsys.readouterr().out
    blob = err.getvalue()
    kwargs = seen["kwargs"]
    if mode == "json":
        assert out == format_devices_json([DEVICE]) + "\n"
        assert blob == ""
        assert "on_step" not in kwargs
        return
    assert out == f"{BANNER}\n\n{format_devices([DEVICE])}\n"
    assert "\r" not in out
    if mode == "quiet":
        assert blob == ""
        assert "on_step" not in kwargs and "stats_every" not in kwargs
    elif mode == "spinner":
        assert "Scanning 192.168.1.0/24…" in blob
        assert re.search(r"\(\d+s\)", blob)
        assert _visible_tail(blob) == ""
        assert "on_step" not in kwargs
    elif mode == "steps":
        assert blob == _STEPS
        assert "\r" not in blob
        assert "stats_every" not in kwargs and "on_progress" not in kwargs
    elif mode == "stats":
        assert blob == _STEPS + _PROGRESS
        assert "\x1b" not in blob
        assert kwargs["stats_every"] == 5
    else:
        assert "\rRunning nmap…\n" in blob
        assert _visible_tail(blob) == ""


@pytest.mark.parametrize(
    ("command", "fn"),
    [("baseline", "take_baseline"), ("new-devices", "check_new_devices")],
)
def test_snapshot_commands_use_the_baseline_api(command, fn, monkeypatch):
    seen: dict = {}

    def fake(target=None, **kwargs):
        seen["target"] = target
        seen["kwargs"] = kwargs
        if command == "baseline":
            return "baseline.json", []
        return DeviceDiff()

    monkeypatch.setattr(
        netinfo, "detect", lambda: NetInfo("eth0", "192.168.1.100", "192.168.1.1", NET)
    )
    if command == "new-devices":
        monkeypatch.setattr(baseline, "load_baseline", lambda path=None: [])
    monkeypatch.setattr(baseline, fn, fake)
    assert main([command]) == 0
    assert seen["target"] == NET
    assert seen["kwargs"]["local_network"] == NET
    assert seen["kwargs"]["resolve_names"] is True


def test_speed_progress_shows_warmup_then_clears(monkeypatch, capsys):
    result = SpeedResult(
        215.2,
        50_000_000,
        7.0,
        "https://speed.cloudflare.com/__down",
        connections=4,
        warmup_s=1.0,
        total_bytes=60_000_000,
    )
    warm = "Testing download speed... 1s of 8s, warming up"
    later = "Testing download speed... 3s of 8s, about 212 Mbps so far"

    def measure(**kwargs):
        progress = kwargs.get("on_progress")
        if progress is not None:
            progress(1.0, 8.0, 0.0)
            progress(3.0, 8.0, 212.4)
        return result

    def run(argv, tty):
        err = _Err(tty)
        monkeypatch.setattr(sys, "stderr", err)
        monkeypatch.setattr(speed, "measure_download", measure)
        assert main(argv) == 0
        return capsys.readouterr().out, err.getvalue()

    out, blob = run(["speed"], True)
    assert f"\r{warm}" in blob and f"\r{later}" in blob
    assert "\n" not in blob and _visible_tail(blob) == ""
    assert out == format_speed(result) + "\n"
    assert "\r" not in out and warm not in out

    out, blob = run(["speed"], False)
    assert blob == f"{warm}\n{later}\n"
    assert "\r" not in blob and out == format_speed(result) + "\n"

    out, blob = run(["speed", "--json"], True)
    assert blob == ""
    assert out == format_speed_json(result) + "\n"
    assert warm not in out and "\r" not in out

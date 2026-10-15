"""-vv support: --stats-every, streamed nmap stderr (on_progress) and on_step messages."""

import io
import subprocess
import sys

import pytest

from homenet.core import baseline, commands, devices, ports, runner
from homenet.core.commands import plan_ports, plan_scan, plan_services
from homenet.core.runner import DisallowedFlagError, ScanResult, build_scan_command, check_flags

NET = "192.168.1.0/24"
# Captured at import, before conftest's autouse guard; only runs the Python interpreter.
_REAL_POPEN = subprocess.Popen


class FakePopen:
    instances = []

    def __init__(self, argv, *, stdout, stderr, text, shell, hang=False):
        assert shell is False and isinstance(argv, list) and text
        self.argv, self.hang, self.killed = argv, hang, False
        self.stdout = io.StringIO("<nmaprun/>")
        self.stderr = io.StringIO("Stats: 0:00:05 elapsed\nPing Scan Timing: About 40% done\n")
        self.returncode = None
        FakePopen.instances.append(self)

    def wait(self, timeout=None):
        if self.hang and not self.killed:
            raise subprocess.TimeoutExpired(self.argv, timeout)
        self.returncode = -9 if self.killed else 0
        return self.returncode

    def kill(self):
        self.killed = True

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.stdout.close()
        self.stderr.close()
        self.wait()


@pytest.fixture
def popen(monkeypatch):
    FakePopen.instances = []
    monkeypatch.setattr(commands.subprocess, "Popen", FakePopen)
    monkeypatch.setattr("shutil.which", lambda n: f"/usr/bin/{n}")
    return FakePopen


def test_stats_every_in_built_and_planned_argv():
    cmd = build_scan_command(NET, local_network=NET, stats_every=5)
    assert cmd.argv[1:4] == ("-sn", "--stats-every", "5s")
    assert plan_scan(local_network=NET, stats_every=5)[0].argv == cmd.argv
    assert "--stats-every" in plan_ports("192.168.1.5", local_network=NET, stats_every=2)[0].argv
    assert "10s" in plan_services("192.168.1.5", local_network=NET, stats_every=10)[0].argv
    assert "--stats-every" not in build_scan_command(NET, local_network=NET).argv


@pytest.mark.parametrize("value", [0, -1, 3601, 1.5, "5s", "5", True, "5m"])
def test_stats_every_refuses_other_values(value):
    with pytest.raises(DisallowedFlagError):
        build_scan_command(NET, local_network=NET, stats_every=value)


@pytest.mark.parametrize("flag", ["--stats-every=5s", "--stats-every=1m"])
def test_stats_every_only_in_exact_form(flag):
    with pytest.raises(DisallowedFlagError):
        check_flags([flag])


def test_on_progress_streams_stderr_and_keeps_stdout(popen):
    lines = []
    res = runner.run_scan(NET, local_network=NET, stats_every=5, on_progress=lines.append)
    assert lines == ["Stats: 0:00:05 elapsed", "Ping Scan Timing: About 40% done"]
    assert res.xml == "<nmaprun/>"
    assert popen.instances[0].argv == list(
        build_scan_command(NET, local_network=NET, stats_every=5).argv
    )


def test_on_progress_callback_errors_are_ignored(popen):
    def broken(line):
        raise RuntimeError("UI exploded")

    assert runner.run_scan(NET, local_network=NET, on_progress=broken).returncode == 0


def test_on_progress_timeout_kills(monkeypatch, popen):
    monkeypatch.setattr(
        commands.subprocess, "Popen", lambda argv, **kw: FakePopen(argv, **kw, hang=True)
    )
    with pytest.raises(runner.NmapTimeoutError):
        runner.run_scan(NET, local_network=NET, timeout=1, on_progress=lambda line: None)
    assert popen.instances[0].killed


def test_without_on_progress_uses_run_not_popen(monkeypatch, popen):
    from types import SimpleNamespace

    monkeypatch.setattr(
        commands.subprocess,
        "run",
        lambda argv, **kw: SimpleNamespace(returncode=0, stdout="<nmaprun/>", stderr=""),
    )
    runner.run_scan(NET, local_network=NET)
    assert popen.instances == []


def _fake_scan(load_fixture, seen_kw):
    def scan(target, mode, *args, **kw):
        seen_kw.append(kw)
        return ScanResult(("nmap",), load_fixture("nmap_sn_hosts.xml"), "", 0)

    return scan


def test_sweep_steps_in_order(load_fixture):
    steps, kw = [], []

    def progress(line):  # passed through to the scan function untouched
        return None

    devices.sweep(
        NET,
        local_network=NET,
        scan=_fake_scan(load_fixture, kw),
        resolver=lambda ip: None,
        stats_every=3,
        on_progress=progress,
        on_step=steps.append,
    )
    assert steps == [f"Scanning {NET}", "Parsed 5 hosts", "Resolving names…"]
    assert kw[0]["stats_every"] == 3 and kw[0]["on_progress"] is progress


@pytest.mark.parametrize(
    ("fn", "first"),
    [
        (ports.scan_ports, "Scanning the top 100 ports on 192.168.1.1/32"),
        (ports.scan_services, "Detecting services on 192.168.1.1/32"),
    ],
)
def test_ports_and_services_steps(fn, first, load_fixture):
    steps = []
    fn("192.168.1.1", local_network=NET, scan=_fake_scan(load_fixture, []), on_step=steps.append)
    assert steps == [first, "Parsed 5 hosts"]


def test_baseline_flow_steps(tmp_path):
    steps = []

    def fake_sweep(target, *, on_step=None, **kw):
        on_step("Scanning x")
        return [devices.Device("192.168.1.1")]

    path = tmp_path / "b.json"
    baseline.take_baseline(path=path, sweep_fn=fake_sweep, on_step=steps.append)
    diff = baseline.check_new_devices(path=path, sweep_fn=fake_sweep, on_step=steps.append)
    assert steps == [
        "Scanning x",
        "Saving baseline (1 device)",
        "Loading baseline",
        "Scanning x",
        "Comparing with baseline",
    ]
    assert not diff.has_changes


def test_on_step_errors_are_ignored(load_fixture):
    def broken(msg):
        raise RuntimeError

    assert devices.sweep(
        NET,
        local_network=NET,
        scan=_fake_scan(load_fixture, []),
        resolve_names=False,
        on_step=broken,
    )


class CapturingPopen(_REAL_POPEN):
    last = None

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        CapturingPopen.last = self


@pytest.fixture
def real_child(monkeypatch):
    monkeypatch.setattr(commands.subprocess, "Popen", CapturingPopen)
    return CapturingPopen


def _py(code):
    return commands.Command((sys.executable, "-c", code), "test child")


def test_real_child_pipes_closed_after_normal_exit(real_child):
    lines = []
    code = "import sys; print('<x/>'); sys.stderr.write('a\\x1b[2Jb\\n\\n')"
    res = commands.stream_command(_py(code), 10, lines.append)
    p = real_child.last
    assert res.returncode == 0 and res.stdout.strip() == "<x/>"
    assert p.stdout.closed and p.stderr.closed and p.returncode == 0
    assert lines == ["a?[2Jb"]  # cleaned; blank line skipped


def test_real_child_killed_and_closed_after_timeout(real_child):
    with pytest.raises(subprocess.TimeoutExpired):
        commands.stream_command(_py("import time; time.sleep(30)"), 0.5, lambda line: None)
    p = real_child.last
    assert p.returncode is not None  # killed and reaped
    assert p.stdout.closed and p.stderr.closed


def test_killed_on_any_exception(monkeypatch, popen):
    def interrupted_wait(self, timeout=None):
        if not self.killed:
            raise KeyboardInterrupt
        return -9

    monkeypatch.setattr(FakePopen, "wait", interrupted_wait)
    with pytest.raises(KeyboardInterrupt):
        runner.run_scan(NET, local_network=NET, on_progress=lambda line: None)
    p = popen.instances[0]
    assert p.killed and p.stdout.closed and p.stderr.closed


def test_streaming_nonzero_exit_keeps_returncode_and_stderr(monkeypatch, popen):
    def failing(argv, **kw):
        p = FakePopen(argv, **kw)
        p.stdout, p.stderr = io.StringIO(""), io.StringIO("boom\n")
        p.wait = lambda timeout=None: setattr(p, "returncode", 2) or 2
        return p

    monkeypatch.setattr(commands.subprocess, "Popen", failing)
    lines = []
    with pytest.raises(runner.NmapFailedError) as ei:
        runner.run_scan(NET, local_network=NET, on_progress=lines.append)
    assert ei.value.returncode == 2 and ei.value.stderr == "boom"
    assert lines == ["boom"]


def test_progress_lines_are_cleaned(monkeypatch, popen):
    def hostile(argv, **kw):
        p = FakePopen(argv, **kw)
        p.stderr = io.StringIO("Stats\x1b]0;pwn\x07 50%\r\n\x9b2J\n")
        return p

    monkeypatch.setattr(commands.subprocess, "Popen", hostile)
    lines = []
    runner.run_scan(NET, local_network=NET, on_progress=lines.append)
    assert lines == ["Stats?]0;pwn? 50%?", "?2J"]
    assert not any(c in "".join(lines) for c in "\x1b\x07\x9b\r")

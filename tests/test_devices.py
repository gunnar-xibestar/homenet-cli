import socket
import subprocess
import sys
import textwrap
import threading
import time
from pathlib import Path

import pytest

from homenet.core.devices import (
    detect_local_network,
    find_device,
    get_device,
    mdns_name,
    normalize_mac,
    resolve_all,
    resolve_name,
    reverse_dns,
    sweep,
)
from homenet.core.parser import Device
from homenet.core.runner import NmapNotFoundError, ScanResult, TargetNotAllowedError, run_scan

NET = "192.168.1.0/24"

# Captured at import, before conftest's autouse guard replaces subprocess.Popen.
# Only used to run the Python interpreter itself, never nmap/ping/ip.
_REAL_POPEN = subprocess.Popen
SRC = Path(__file__).resolve().parents[1] / "src"


def fake_scan(load_fixture, calls=None):
    def scan(target, mode, **kw):
        if calls is not None:
            calls.append((target, mode, kw))
        return ScanResult(("nmap",), load_fixture("nmap_sn_hosts.xml"), "", 0)

    return scan


def test_sweep_uses_ping_mode_and_local_network(load_fixture):
    calls = []
    devices = sweep(
        NET, local_network=NET, timeout=7, scan=fake_scan(load_fixture, calls), resolve_names=False
    )
    assert calls == [(NET, "ping", {"local_network": NET, "force": False, "timeout": 7})]
    assert len(devices) == 5


def test_sweep_resolves_only_missing_names(load_fixture):
    asked = []

    def resolver(ip):
        asked.append(ip)
        return "tv.local" if ip == "192.168.1.42" else None

    devices = {
        d.ip: d
        for d in sweep(NET, local_network=NET, scan=fake_scan(load_fixture), resolver=resolver)
    }
    assert asked == ["192.168.1.42", "192.168.1.77"]
    assert devices["192.168.1.42"].hostname == "tv.local"
    assert devices["192.168.1.77"].hostname is None
    assert devices["192.168.1.1"].hostname == "router.lan"


def test_sweep_propagates_runner_errors():
    def scan(*a, **k):
        raise NmapNotFoundError("nmap is not installed.")

    with pytest.raises(NmapNotFoundError):
        sweep(NET, local_network=NET, scan=scan)


def test_reverse_dns():
    assert reverse_dns("192.168.1.1", lookup=lambda ip: ("router.lan", [], [ip])) == "router.lan"

    def fail(ip):
        raise socket.herror(1, "Unknown host")

    assert reverse_dns("192.168.1.9", lookup=fail) is None


def test_mdns_with_avahi(load_fixture):
    calls = []

    def run(args):
        calls.append(args)
        return load_fixture("avahi_resolve_a.txt")

    name = mdns_name("192.168.1.42", which=lambda n: "/usr/bin/avahi-resolve", run=run)
    assert name == "gunnars-macbook.local"
    assert calls == [["/usr/bin/avahi-resolve", "-a", "192.168.1.42"]]


def test_mdns_degrades_gracefully():
    assert mdns_name("192.168.1.42", which=lambda n: None) is None

    def boom(args):
        raise OSError("no daemon")

    assert mdns_name("192.168.1.42", which=lambda n: "/x", run=boom) is None
    assert mdns_name("192.168.1.42", which=lambda n: "/x", run=lambda a: "") is None
    assert mdns_name("not-an-ip; rm", which=lambda n: "/x", run=boom) is None


def test_resolve_name_order():
    assert resolve_name("1", reverse=lambda ip: "a", mdns=lambda ip: "b") == "a"
    assert resolve_name("1", reverse=lambda ip: None, mdns=lambda ip: "b") == "b"
    assert resolve_name("1", reverse=lambda ip: None, mdns=lambda ip: None) is None


@pytest.mark.parametrize(
    ("raw", "norm"),
    [
        ("A4:2B:B0:11:22:33", "a4:2b:b0:11:22:33"),
        ("a4-2b-b0-11-22-33", "a4:2b:b0:11:22:33"),
        (None, None),
        ("", None),
    ],
)
def test_normalize_mac(raw, norm):
    assert normalize_mac(raw) == norm


def test_find_device():
    devs = [Device("192.168.1.1", "A4:2B:B0:11:22:33"), Device("192.168.1.2")]
    assert find_device(devs, mac="a4-2b-b0-11-22-33").ip == "192.168.1.1"
    assert find_device(devs, ip="192.168.1.2").ip == "192.168.1.2"
    assert find_device(devs, ip="192.168.1.9") is None
    with pytest.raises(ValueError):
        find_device(devs)


def test_get_device(load_fixture):
    d = get_device(
        local_network=NET,
        mac="b8:27:eb:aa:bb:cc",
        scan=fake_scan(load_fixture),
        resolve_names=False,
    )
    assert d.ip == "192.168.1.23"
    assert (
        get_device(
            local_network=NET, ip="192.168.1.250", scan=fake_scan(load_fixture), resolve_names=False
        )
        is None
    )
    with pytest.raises(ValueError):
        get_device(local_network=NET)


def guarded_scan(load_fixture, calls):
    """Real run_scan validation, fake nmap execution."""

    def scan(target, mode, **kw):
        from homenet.core.runner import build_args

        calls.append(build_args(target, mode, local_network=kw["local_network"], force=kw["force"]))
        return ScanResult(("nmap",), load_fixture("nmap_sn_no_hosts.xml"), "", 0)

    return scan


def test_other_private_subnet_refused_without_force(load_fixture):
    calls = []
    with pytest.raises(TargetNotAllowedError, match="outside your local subnet"):
        sweep("10.0.50.0/24", local_network=NET, scan=guarded_scan(load_fixture, calls))
    assert calls == []
    assert (
        sweep("10.0.50.0/24", local_network=NET, force=True, scan=guarded_scan(load_fixture, calls))
        == []
    )
    assert calls[0][-1] == "10.0.50.0/24"


def test_real_run_scan_refuses_before_nmap(monkeypatch):
    # run_scan itself (subprocess blocked by conftest) must refuse before spawning nmap
    with pytest.raises(TargetNotAllowedError):
        sweep("10.0.50.0/24", local_network=NET, scan=run_scan)


def test_local_network_detected_from_default_route(load_fixture, load_json_fixture):
    def ip_runner(args):
        return load_fixture("ip_route.json" if args[1] == "route" else "ip_addr.json")

    assert str(detect_local_network(ip_runner)) == NET
    calls = []
    sweep(local_network=None, ip_runner=ip_runner, scan=guarded_scan(load_fixture, calls))
    assert calls[0][-1] == NET  # target defaults to the default-route subnet
    with pytest.raises(TargetNotAllowedError):  # docker0 is not "local"
        sweep("172.17.0.0/24", ip_runner=ip_runner, scan=guarded_scan(load_fixture, calls))


def test_no_local_network_detected():
    def broken(args):
        raise OSError("ip missing")

    assert detect_local_network(broken) is None
    with pytest.raises(TargetNotAllowedError, match="Could not detect"):
        sweep(ip_runner=broken, scan=lambda *a, **k: None)


def test_resolve_all_respects_budget():
    release = threading.Event()

    def slow(ip):
        if ip.endswith(".9"):
            release.wait(5)  # simulates a hung DNS server
            return "late.lan"
        return f"host-{ip}"

    start = time.monotonic()
    names = resolve_all(["192.168.1.1", "192.168.1.9", "192.168.1.2"], slow, budget=0.2)
    elapsed = time.monotonic() - start
    release.set()
    assert elapsed < 1.0
    assert names == {
        "192.168.1.1": "host-192.168.1.1",
        "192.168.1.9": None,
        "192.168.1.2": "host-192.168.1.2",
    }


def test_resolve_all_runs_concurrently():
    def slow(ip):
        time.sleep(0.1)
        return ip

    start = time.monotonic()
    names = resolve_all([f"192.168.1.{i}" for i in range(20)], slow, budget=2)
    assert time.monotonic() - start < 1.0 and len(names) == 20 and all(names.values())


def test_resolve_all_errors_and_empty():
    def boom(ip):
        raise RuntimeError("x")

    assert resolve_all(["192.168.1.1"], boom) == {"192.168.1.1": None}
    assert resolve_all([], boom) == {}


def test_sweep_with_slow_resolver_is_bounded(load_fixture):
    release = threading.Event()

    def hang(ip):
        release.wait(5)
        return "late"

    start = time.monotonic()
    devices = sweep(
        NET, local_network=NET, scan=fake_scan(load_fixture), resolver=hang, resolve_budget=0.2
    )
    release.set()
    assert time.monotonic() - start < 1.0
    assert {d.ip: d.hostname for d in devices}["192.168.1.42"] is None


def test_mdns_default_runner_gets_timeout(monkeypatch):
    from homenet.core import devices as dev

    seen = {}

    def fake_avahi(args, timeout):
        seen["timeout"] = timeout
        return ""

    monkeypatch.setattr(dev, "_run_avahi", fake_avahi)
    assert mdns_name("192.168.1.42", which=lambda n: "/x", timeout=0.5) is None
    assert seen == {"timeout": 0.5}


def test_resolver_workers_are_daemon_threads():
    seen = []

    def record(ip):
        seen.append(threading.current_thread().daemon)
        return None

    resolve_all(["192.168.1.1", "192.168.1.2"], record, budget=2)
    assert seen == [True, True]


def test_hung_lookup_does_not_block_process_exit():
    code = textwrap.dedent(
        """
        import sys, threading, time
        sys.path.insert(0, sys.argv[1])
        from homenet.core.devices import resolve_all
        hang = threading.Event()
        start = time.monotonic()
        names = resolve_all(["192.168.1.9"], lambda ip: hang.wait(30), budget=1.0)
        if names != {"192.168.1.9": None}:
            sys.exit(2)
        elapsed = time.monotonic() - start
        if elapsed >= 2.0:
            sys.exit(3)
        print(round(elapsed, 2))
        sys.exit(0)
        """
    )
    start = time.monotonic()
    with _REAL_POPEN(
        [sys.executable, "-c", code, str(SRC)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ) as proc:
        try:
            stdout, stderr = proc.communicate(timeout=20)
        except subprocess.TimeoutExpired:
            proc.kill()
            raise
    elapsed = time.monotonic() - start
    assert proc.returncode == 0, stderr
    assert float(stdout) < 2.0
    assert elapsed < 10  # the fake lookup hangs for 30s; exit must not wait for it

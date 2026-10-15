"""Displayed commands == executed commands; planners validate but never run anything."""

import subprocess
from types import SimpleNamespace

import pytest

from homenet.core import checks, commands, devices, netinfo, router, runner, speed
from homenet.core.commands import (
    Command,
    plan_doctor,
    plan_ports,
    plan_router,
    plan_scan,
    plan_services,
    plan_speed,
    plan_whoami,
    planned_commands,
    set_command_hook,
)
from homenet.core.router import FetchResult
from homenet.core.runner import DisallowedFlagError, InvalidTargetError, TargetNotAllowedError

NET = "192.168.1.0/24"
ROUTE = (
    "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"
    "wlp2s0\t00000000\t0101A8C0\t3\t0\t0\t600\t0\n"
)
WHICH = {"nmap": "/usr/bin/nmap", "ip": "/usr/bin/ip", "ping": "/bin/ping"}


@pytest.fixture
def seen():
    got = []
    set_command_hook(got.append)
    yield got
    set_command_hook(None)


@pytest.fixture
def executed(monkeypatch):
    """Replace the only executor (subprocess.run via commands.run_command)."""
    argvs = []

    def fake_run(argv, **kw):
        assert kw["shell"] is False and isinstance(argv, list)
        argvs.append(tuple(argv))
        out = {"nmap": "<nmaprun/>", "ip": "[]", "ping": "0% packet loss"}.get(
            argv[0].rsplit("/", 1)[-1], "192.168.1.42\tbox.local\n"
        )
        return SimpleNamespace(returncode=0, stdout=out, stderr="")

    monkeypatch.setattr(commands.subprocess, "run", fake_run)
    monkeypatch.setattr("shutil.which", lambda n: WHICH.get(n, f"/usr/bin/{n}"))
    return argvs


def test_display_and_dict():
    c = Command(("nmap", "-sn", "a b"), "p")
    assert c.display() == "nmap -sn 'a b'"
    h = commands.http_command("http://192.168.1.1/", "p", 3)
    assert h.display() == "curl -sS --max-time 3 http://192.168.1.1/"
    assert h.to_dict() == {
        "argv": ["http://192.168.1.1/"],
        "display": h.display(),
        "purpose": "p",
        "kind": "http",
    }


# ---- one test per wrapper: executed argv == built argv, hook sees it first ----


def _run_scan():
    runner.run_scan("192.168.1.0/24", local_network=NET)
    return [runner.build_scan_command("192.168.1.0/24", local_network=NET)]


def _run_ip():
    with pytest.raises(netinfo.NetInfoError):  # "[]" = no default route
        netinfo.detect()
    return [netinfo.build_ip_command(netinfo.ROUTE_ARGS)]


def _run_doctor():
    checks.check_tool("nmap")
    checks.check_ping("192.168.1.1")
    return [
        checks.build_version_command("nmap", "/usr/bin/nmap"),
        checks.build_ping_command("192.168.1.1", "/bin/ping"),
    ]


def _run_avahi():
    assert devices.mdns_name("192.168.1.42") == "box.local"
    return [devices.build_avahi_command("192.168.1.42", "/usr/bin/avahi-resolve")]


def _run_router(fetched):
    def fetch(url, timeout, verify):
        fetched.append(url)
        return FetchResult(200, {}, "")

    router.check_router_admin("192.168.1.1", local_network=NET, fetch=fetch)
    return plan_router("192.168.1.1", local_network=NET)


def _run_speed(fetched):
    speed.measure_download(nbytes=1000, fetch=lambda u, t, n: fetched.append(u) or b"x" * n)
    return plan_speed(nbytes=1000)


@pytest.mark.parametrize(
    ("wrapper", "kind"),
    [
        (_run_scan, "exec"),
        (_run_ip, "exec"),
        (_run_doctor, "exec"),
        (_run_avahi, "exec"),
        (_run_router, "http"),
        (_run_speed, "http"),
    ],
    ids=["nmap", "ip", "doctor", "avahi", "router", "speed"],
)
def test_wrapper_runs_exactly_the_built_command(wrapper, kind, executed, seen):
    """What the hook sees == what was built/planned == what actually ran or was fetched."""
    if kind == "exec":
        built = wrapper()
        assert executed == [c.argv for c in built]
    else:
        fetched = []
        built = wrapper(fetched)
        assert fetched == [c.url for c in built] and executed == []
    assert [(c.argv, c.kind) for c in seen] == [(c.argv, c.kind) for c in built]


# ---- planners never execute and still validate ----


def test_planners_never_call_subprocess(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("planner executed something")

    for name in ("run", "Popen"):
        monkeypatch.setattr(subprocess, name, boom)
    fetch_guard = []
    monkeypatch.setattr(router, "http_get", lambda *a, **k: fetch_guard.append(a))
    plans = [
        plan_scan(local_network=NET),
        plan_ports("192.168.1.5", local_network=NET),
        plan_services("192.168.1.5", local_network=NET),
        plan_whoami(),
        plan_doctor("192.168.1.1", which=WHICH.get),
        plan_router("192.168.1.1", local_network=NET),
        plan_speed(),
        planned_commands("new-devices", local_network=NET),
    ]
    assert all(p and all(isinstance(c, Command) for c in p) for p in plans)
    assert fetch_guard == []
    assert plans[0][0].argv[1] == "-sn" and plans[2][0].argv[1:4] == (
        "-sT",
        "-sV",
        "--version-light",
    )
    assert [c.display() for c in plans[3]] == ["ip -j route show", "ip -j addr show"]
    assert [c.argv[0] for c in plans[4]] == ["/usr/bin/nmap", "/usr/bin/ip", "/bin/ping"]


def test_plan_doctor_reads_gateway_from_proc():
    cmds = plan_doctor(which=WHICH.get, read_text=lambda p: ROUTE)
    assert cmds[-1].argv[-1] == "192.168.1.1"


@pytest.mark.parametrize(
    ("plan", "kwargs", "error"),
    [
        (plan_scan, {"target": "10.0.0.0/24", "local_network": NET}, TargetNotAllowedError),
        (
            plan_scan,
            {"target": "8.8.8.8", "local_network": NET, "force": True},
            TargetNotAllowedError,
        ),
        (
            plan_scan,
            {"target": "192.168.0.0/15", "local_network": NET, "force": True},
            TargetNotAllowedError,
        ),
        (plan_scan, {}, TargetNotAllowedError),
        (plan_ports, {"target": "172.17.0.2", "local_network": NET}, TargetNotAllowedError),
        (
            plan_ports,
            {"target": "192.168.1.5", "local_network": NET, "top_ports": 5000},
            DisallowedFlagError,
        ),
        (plan_services, {"target": NET, "local_network": NET}, InvalidTargetError),
        (plan_router, {"gateway": "10.0.0.1", "local_network": NET}, TargetNotAllowedError),
        (plan_router, {"gateway": "192.168.1.1"}, TargetNotAllowedError),
        (plan_speed, {"url": "http://example.com/"}, speed.SpeedError),
        (plan_speed, {"nbytes": 10**9}, speed.SpeedError),
    ],
)
def test_planners_still_refuse(plan, kwargs, error):
    with pytest.raises(error):
        plan(**kwargs)


def test_plan_scan_force_allows_other_private_subnet():
    assert plan_scan("10.0.0.0/24", local_network=NET, force=True)[0].argv[-1] == "10.0.0.0/24"


def test_planned_commands_dispatch():
    assert planned_commands("whoami-net") == plan_whoami()
    with pytest.raises(ValueError, match="Unknown command"):
        planned_commands("hack-the-planet")

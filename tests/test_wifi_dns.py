"""Wi-Fi and DNS core: fixture parsers, unavailable reasons, commands == planned."""

import socket
import subprocess
import threading
import time

import pytest

from homenet.core import checks, commands, dns, wifi
from homenet.core.commands import planned_commands, set_command_hook

TOOLS = {"nmcli": "/usr/bin/nmcli", "iw": "/usr/sbin/iw", "resolvectl": "/usr/bin/resolvectl"}
SYS = {
    "listdir": lambda p: ["lo", "eth0", "wlp2s0"],
    "exists": lambda p: p == "/sys/class/net/wlp2s0/wireless",
}


def fake_run(load_fixture, nmcli="nmcli_device_connected.txt", iw="iw_link_5ghz.txt"):
    calls = []

    def run(argv):
        calls.append(tuple(argv))
        if argv[0].endswith("nmcli"):
            if "device" in argv:
                return load_fixture(nmcli)
            return "802-11-wireless.ssid:Home\\:WiFi\x1b[2J\n"
        return load_fixture(iw)

    run.calls = calls
    return run


def info(run, which=TOOLS.get, wsl=False, **kw):
    return wifi.get_wifi_info(which=which, run=run, wsl_check=lambda: wsl, **SYS, **kw)


@pytest.mark.parametrize(
    ("mhz", "channel", "band"),
    [
        (2412, 1, "2.4 GHz"),
        (2484, 14, "2.4 GHz"),
        (5180, 36, "5 GHz"),
        (5825, 165, "5 GHz"),
        (5955, 1, "6 GHz"),
        (6415, 93, "6 GHz"),
        (900, None, None),
        (None, None, None),
    ],
)
def test_channel_and_band(mhz, channel, band):
    assert (wifi.channel_from_frequency(mhz), wifi.band_from_frequency(mhz)) == (channel, band)


@pytest.mark.parametrize(
    ("fixture", "expected"),
    [
        (
            "iw_link_5ghz.txt",
            {
                "ssid": "Home WiFi",
                "frequency_mhz": 5180,
                "signal_dbm": -52,
                "link_speed_mbps": 866.7,
            },
        ),
        ("iw_link_disconnected.txt", {}),
    ],
)
def test_parse_iw_link(load_fixture, fixture, expected):
    assert wifi.parse_iw_link(load_fixture(fixture)) == expected


@pytest.mark.parametrize(("percent", "dbm"), [(0, -100), (50, -75), (100, -50), (150, -50)])
def test_percent_to_dbm(percent, dbm):
    assert wifi.percent_to_dbm(percent) == dbm


@pytest.mark.parametrize(("dbm", "percent"), [(-110, 0), (-100, 0), (-75, 50), (-50, 100)])
def test_dbm_to_percent(dbm, percent):
    assert wifi.dbm_to_percent(dbm) == percent


@pytest.mark.parametrize(
    ("text", "expected"),
    [("A:b\\:c", {"A": "b:c"}), ("A:x\\\\:y", {"A": "x\\:y"}), ("A:a\\\\\\:b", {"A": "a\\:b"})],
    ids=["colon", "backslash-then-colon", "escaped-backslash-and-colon"],
)
def test_parse_nmcli_escapes(text, expected):
    assert wifi.parse_nmcli_fields(text) == expected


def test_connected_nmcli_then_iw(load_fixture):
    run, steps = fake_run(load_fixture), []
    seen = []
    set_command_hook(seen.append)
    try:
        w = info(run, on_step=steps.append)
    finally:
        set_command_hook(None)
    assert w == wifi.WifiInfo(
        True,
        interface="wlp2s0",
        ssid="Home:WiFi?[2J",
        signal_dbm=-52,
        signal_percent=96,
        channel=36,
        frequency_mhz=5180,
        band="5 GHz",
        link_speed_mbps=866.7,
    )
    # executed == hook == planned (SSID step needs the runtime connection name)
    planned = commands.plan_wifi(connection="Home WiFi", which=TOOLS.get, **SYS)
    assert run.calls == [c.argv for c in seen] == [c.argv for c in planned]
    assert planned_commands("wifi", which=TOOLS.get, **SYS)[0].display() == (
        "/usr/bin/nmcli -t -f GENERAL.STATE,GENERAL.CONNECTION device show wlp2s0"
    )
    assert not any("list" in c.argv or "rescan" in c.argv for c in planned)
    assert steps[0] == "Looking for a Wi-Fi interface"


def test_iw_only(load_fixture):
    w = info(fake_run(load_fixture), which={"iw": "/usr/sbin/iw"}.get)
    assert w.available and w.ssid == "Home WiFi" and w.band == "5 GHz"


@pytest.mark.parametrize(
    ("kw", "nmcli", "iw", "reason"),
    [
        ({"wsl_check": lambda: True}, None, None, "WSL"),
        ({"listdir": lambda p: ["lo", "eth0"]}, None, None, "no Wi-Fi interface"),
        ({"which": lambda n: None}, None, None, "nmcli/iw not installed"),
        ({}, "nmcli_device_disconnected.txt", None, "not connected"),
        ({"which": {"iw": "/usr/sbin/iw"}.get}, None, "iw_link_disconnected.txt", "not connected"),
    ],
    ids=["wsl", "no-iface", "no-tools", "nmcli-disconnected", "iw-disconnected"],
)
def test_unavailable_reasons(load_fixture, kw, nmcli, iw, reason):
    run = fake_run(load_fixture, nmcli or "nmcli_device_connected.txt", iw or "iw_link_5ghz.txt")
    args = {"which": TOOLS.get, "wsl_check": lambda: False, **SYS, **kw}
    w = wifi.get_wifi_info(run=run, **args)
    assert (w.available, w.reason, w.wsl) == (False, reason, reason == "WSL")


ERRORS = [
    OSError("boom"),
    subprocess.CalledProcessError(1, ["x"]),
    subprocess.TimeoutExpired(["x"], 5),
]


@pytest.mark.parametrize("error", ERRORS, ids=["oserror", "nonzero", "timeout"])
@pytest.mark.parametrize("tool", ["nmcli", "iw"])
def test_command_errors_never_raise(error, tool):
    def broken(argv):
        raise error

    w = info(broken, which={tool: TOOLS[tool]}.get)
    assert (w.available, w.reason) == (False, "not connected")


def test_bad_interface_never_raises():
    w = wifi.get_wifi_info("--evil", which=TOOLS.get, wsl_check=lambda: False)
    assert (w.available, w.reason) == (False, "no Wi-Fi interface")


# ---- DNS ----


@pytest.mark.parametrize(
    ("parser", "fixture", "expected"),
    [
        (
            dns.parse_resolvectl,
            "resolvectl_status.txt",
            [
                ("1.1.1.1", None),
                ("2606:4700:4700::1111", None),
                ("192.168.1.1", "wlp2s0"),
                ("fe80::1", "wlp2s0"),
            ],
        ),
        (dns.parse_resolv_conf, "resolv_conf_stub.txt", [("127.0.0.53", None)]),
        (
            dns.parse_resolv_conf,
            "resolv_conf_plain.txt",
            [("192.168.1.1", None), ("8.8.8.8", None)],
        ),
    ],
)
def test_dns_parsers(load_fixture, parser, fixture, expected):
    assert [(s.ip, s.interface) for s in parser(load_fixture(fixture))] == expected


def _files(load_fixture, name):
    return lambda path: load_fixture(name)


def test_resolvectl_with_stub(load_fixture):
    calls, seen = [], []
    set_command_hook(seen.append)
    try:
        cfg = dns.get_dns_servers(
            which=TOOLS.get,
            read_text=_files(load_fixture, "resolv_conf_stub.txt"),
            run=lambda argv: calls.append(tuple(argv)) or load_fixture("resolvectl_status.txt"),
        )
    finally:
        set_command_hook(None)
    assert cfg.source == "resolvectl" and cfg.uses_systemd_stub
    assert cfg.upstream == ["1.1.1.1", "2606:4700:4700::1111", "192.168.1.1", "fe80::1"]
    assert (
        calls
        == [c.argv for c in seen]
        == [c.argv for c in planned_commands("dns", which=TOOLS.get)]
    )


@pytest.mark.parametrize(
    ("which", "run_out", "conf", "source", "stub", "ips"),
    [
        (
            lambda n: None,
            None,
            "resolv_conf_plain.txt",
            "resolv.conf",
            False,
            ["192.168.1.1", "8.8.8.8"],
        ),
        (TOOLS.get, "", "resolv_conf_stub.txt", "resolv.conf", True, ["127.0.0.53"]),
        (lambda n: None, None, None, None, False, []),
    ],
    ids=["no-resolvectl", "resolvectl-empty", "nothing-readable"],
)
def test_dns_fallbacks(load_fixture, which, run_out, conf, source, stub, ips):
    def read(path):
        if conf is None:
            raise OSError(path)
        return load_fixture(conf)

    cfg = dns.get_dns_servers(which=which, run=lambda a: run_out, read_text=read)
    assert (cfg.source, cfg.uses_systemd_stub, [s.ip for s in cfg.servers]) == (source, stub, ips)
    assert cfg.upstream == []


def _addr(ip):
    return (socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))


@pytest.mark.parametrize(
    ("resolver", "ok", "addresses", "error"),
    [
        (
            lambda *a, **k: [_addr("93.184.216.34"), _addr("93.184.216.34")],
            True,
            ("93.184.216.34",),
            None,
        ),
        (
            lambda *a, **k: (_ for _ in ()).throw(socket.gaierror(-2, "Name not known")),
            False,
            (),
            "gaierror: [Errno -2] Name not known",
        ),
        (lambda *a, **k: [], False, (), "no addresses"),
    ],
    ids=["ok", "nxdomain", "empty"],
)
def test_lookup(resolver, ok, addresses, error):
    r = dns.dns_lookup_test(resolver=resolver)
    assert (r.ok, r.addresses, r.error) == (ok, addresses, error) and r.name == "example.com"


def test_lookup_deadline_with_hung_resolver():
    release = threading.Event()
    seen = []

    def hung(*a, **k):
        seen.append(threading.current_thread().daemon)
        release.wait(5)
        return []

    start = time.monotonic()
    r = dns.dns_lookup_test(timeout=0.2, resolver=hung, on_step=lambda m: None)
    release.set()
    assert time.monotonic() - start < 1 and not r.ok and "timed out" in r.error
    assert seen == [True]


def test_lookup_rejects_bad_names():
    assert dns.dns_lookup_test("-oops\x1b").error == "not a valid host name"


def test_optional_tools_warn_when_missing():
    r = checks.check_optional_tool("nmcli", which=lambda n: None)
    assert (r.ok, r.severity, r.fix_hint) == (False, "warning", "sudo apt install network-manager")
    assert [
        c.name
        for c in checks.run_all_checks(
            which=lambda n: None, read_text=lambda p: "", geteuid=lambda: 0, environ={}
        )
    ] == ["nmap", "ip", "privileges", "network", "ping"]

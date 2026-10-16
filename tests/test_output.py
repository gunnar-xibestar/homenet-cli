"""Plain-text formatters. They never scan and never run system commands."""

import json

import pytest

from homenet.core.baseline import diff_devices, load_baseline
from homenet.core.dns import DnsConfig, DnsServer, LookupResult
from homenet.core.netinfo import NetInfo
from homenet.core.parser import Device, Port, parse_nmap_xml
from homenet.core.port_notes import notes_for_ports
from homenet.core.router import AdminPage, RouterCheck
from homenet.core.speed import SpeedResult
from homenet.core.wifi import WifiInfo
from homenet.output import (
    format_device,
    format_device_json,
    format_devices,
    format_devices_json,
    format_diff,
    format_diff_json,
    format_dns,
    format_error,
    format_ports,
    format_ports_json,
    format_router,
    format_router_json,
    format_services,
    format_services_json,
    format_speed,
    format_speed_json,
    format_whoami,
    format_whoami_json,
    format_wifi,
)

_WHOAMI = """\
This computer on your home network

Interface     wlp2s0
IP address    192.168.1.100
Gateway       192.168.1.1
Home network  192.168.1.0/24
Network size  /24 (256 addresses: 192.168.1.0–192.168.1.255)

The interface is how this computer is connected, such as Wi-Fi.
The IP address is this computer.
The gateway is usually your home router.
The home network is the group of addresses your devices share.\
"""

_DEVICES = """\
Devices on your home network

IP address    Name     MAC address        Maker
192.168.1.2   unknown  unknown            unknown
192.168.1.10  laptop   AA:BB:CC:DD:EE:10  Dell

2 devices found.\
"""

_DEVICE = """\
router.lan (192.168.1.1)

Name         router.lan
IP address   192.168.1.1
MAC address  A4:2B:B0:11:22:33
Maker        TP-Link Technologies

Ports

Number  Protocol  State     What it is
53      udp       open      domain
80      tcp       open      http
443     tcp       filtered  unknown

Open means a program is listening on that port.\
"""


def test_format_whoami_shows_the_address():
    info = NetInfo("wlp2s0", "192.168.1.100", "192.168.1.1", "192.168.1.0/24")
    assert format_whoami(info) == _WHOAMI
    assert "Warning:" not in format_whoami(info)


def test_format_whoami_warns_on_wsl_nat():
    info = NetInfo("eth0", "172.22.240.5", "172.22.240.1", "172.22.240.0/20", wsl_nat=True)
    text = format_whoami(info)
    loaded = json.loads(format_whoami_json(info))
    assert "Warning:" in text and loaded["wsl_nat"] is True
    for blob in (text, loaded["warning"]):
        assert "172.22.240.0/20" in blob
        assert "may be the WSL virtual network" in blob
        assert "networkingMode=mirrored" in blob and "wsl --shutdown" in blob


@pytest.mark.parametrize(
    ("info", "present", "absent"),
    [
        (
            NetInfo("wlp2s0", None, "192.168.1.1", "192.168.1.0/24"),
            ["IP address    not available", "Home network  192.168.1.0/24", "was not available."],
            [],
        ),
        (
            NetInfo("eth0", "10.0.0.5", None, None),
            [
                "IP address    10.0.0.5",
                "Gateway       not available",
                "Home network  not available",
            ],
            ["/not"],
        ),
        (
            NetInfo("eth0", "10.0.0.5", "10.0.0.1", "not-a-network"),
            ["IP address    10.0.0.5\n", "Home network  not-a-network"],
            [],
        ),
        (
            NetInfo("eth0", "10.0.0.5", "10.0.0.1", "fe80::/64"),
            ["IP address    10.0.0.5\n"],
            ["10.0.0.5/64"],
        ),
    ],
    ids=["no-ip", "no-subnet", "bad-subnet", "mixed-version"],
)
def test_format_whoami_missing_or_unusable_fields(info, present, absent):
    text = format_whoami(info)
    assert all(s in text for s in present) and not any(s in text for s in absent)


@pytest.mark.parametrize(
    ("subnet", "count", "start", "end"),
    [
        ("10.1.0.0/16", 65536, "10.1.0.0", "10.1.255.255"),
        ("192.168.1.0/31", 2, "192.168.1.0", "192.168.1.1"),
        ("192.168.1.5/32", 1, "192.168.1.5", "192.168.1.5"),
    ],
    ids=["16", "31", "32"],
)
def test_whoami_network_size_edges(subnet, count, start, end):
    loaded = json.loads(format_whoami_json(NetInfo("eth0", start, None, subnet)))
    assert (loaded["address_count"], loaded["range_start"], loaded["range_end"]) == (
        count,
        start,
        end,
    )


def test_format_error_includes_a_fix_when_one_is_known():
    assert format_error("No default route found.", "Connect to Wi-Fi and try again.") == (
        "No default route found.\nFix: Connect to Wi-Fi and try again."
    )
    assert format_error("Unexpected output.") == "Unexpected output."


def test_format_devices_sorts_by_address_and_names_missing_fields():
    devices = [
        Device("192.168.1.10", "AA:BB:CC:DD:EE:10", "Dell", "laptop"),
        Device("192.168.1.2", None, None, None),
    ]
    assert format_devices(devices) == _DEVICES
    assert [device.ip for device in devices] == ["192.168.1.10", "192.168.1.2"]


def test_format_devices_empty_list_explains_what_to_try():
    assert format_devices(()) == (
        "Devices on your home network\n"
        "\n"
        "No devices were found.\n"
        "\n"
        "Make sure this computer is connected to your home network, then try again."
    )


def test_format_devices_sorts_ipv4_before_ipv6_before_junk():
    text = format_devices(
        [
            Device("2001:db8::2", None, None, "v6"),
            Device("not-an-ip", None, None, "odd"),
            Device("192.168.1.10", None, None, "v4"),
        ]
    )
    assert text.index("192.168.1.10") < text.index("2001:db8::2") < text.index("not-an-ip")


def test_format_devices_accepts_parser_devices(load_fixture):
    devices = parse_nmap_xml(load_fixture("nmap_sn_hosts.xml"))
    text = format_devices(devices)
    rows = [line.split()[0] for line in text.splitlines() if line[:3].isdigit()]
    assert rows == [
        "192.168.1.1",
        "192.168.1.23",
        "192.168.1.42",
        "192.168.1.77",
        "192.168.1.100",
    ]
    assert "router.lan" in text
    assert "TP-Link Technologies" in text
    assert "gunnar-laptop" in text
    assert "5 devices found." in text
    mine = next(line for line in text.splitlines() if line.startswith("192.168.1.100"))
    assert "unknown" in mine


def test_format_device_lists_ports_in_order():
    device = Device(
        "192.168.1.1",
        "A4:2B:B0:11:22:33",
        "TP-Link Technologies",
        "router.lan",
        [
            Port(80, "tcp", "open", "http"),
            Port(443, "tcp", "filtered", None),
            Port(53, "udp", "open", "domain"),
        ],
    )
    assert format_device(device) == _DEVICE


def test_format_device_without_a_name_or_ports():
    text = format_device(Device("192.168.1.77", None, "  ", None, []))
    assert text.startswith("Device 192.168.1.77\n")
    assert "Name         unknown" in text
    assert "MAC address  unknown" in text
    assert "Maker        unknown" in text
    assert text.endswith("No ports were reported for this device.")


# The sanitiser itself is tested in test_text.py; here, one hostile string per call site.
@pytest.mark.parametrize(
    ("render", "expected"),
    [
        (
            lambda: format_devices([Device("192.168.1.5", None, "Evil\x1b]0;x", "x\x1b[2Jy")]),
            "x?[2Jy",
        ),
        (
            lambda: format_device(
                Device("192.168.1.9\x1b[2J", None, None, "pc", [Port(80, "tc\x1bp", "op\x1ben")])
            ),
            "pc (192.168.1.9?[2J)",
        ),
        (lambda: format_whoami(NetInfo("eth0", "10.0.0.5\x1b[2J", None, "nope")), "10.0.0.5?[2J"),
        (lambda: format_error("eth0\x1b[2J.", "wlan0\x07."), "eth0?[2J.\nFix: wlan0?."),
    ],
    ids=["devices", "device", "whoami", "error"],
)
def test_call_sites_sanitise_network_text(render, expected):
    text = render()
    assert "\x1b" not in text and "\x07" not in text and expected in text


_DIFF = """\
Changes since your saved snapshot

New
These devices were not in your saved snapshot.

IP address    Name     MAC address        Maker
192.168.1.42  unknown  3C:22:FB:44:55:66  Apple
192.168.1.77  unknown  7C:2F:80:DE:AD:01  unknown

Missing
These devices were in your saved snapshot but are not on the network now.

IP address    Name     MAC address        Maker
192.168.1.50  unknown  00:11:22:33:44:55  Old Printer Co

Changed
A detail changed on these devices.

pihole.lan (192.168.1.23)

IP address  was 192.168.1.20, now 192.168.1.23

2 new devices. 1 missing device. 1 changed device.\
"""

_NO_CHANGES = (
    "No changes since your saved snapshot.\n"
    "\n"
    "The devices on your network match the snapshot you saved with `homenet baseline`."
)


def test_format_diff_reports_new_missing_and_changed(load_fixture, fixtures_dir):
    old = load_baseline(fixtures_dir / "baseline_v1.json")
    current = parse_nmap_xml(load_fixture("nmap_sn_hosts.xml"))
    assert format_diff(diff_devices(old, current)) == _DIFF


def test_format_diff_says_when_nothing_changed():
    device = Device("192.168.1.1", "aa:aa:aa:aa:aa:aa", "Router", "router")
    assert format_diff(diff_devices([device], [device])) == _NO_CHANGES


def test_format_diff_flags_a_mac_change_as_spoof_or_replaced():
    old = Device("192.168.1.5", "aa:aa:aa:aa:aa:aa", "Old\x1bCo", None)
    current = Device("192.168.1.5", "bb:bb:bb:bb:bb:bb", "New\x1bCo", None)
    text = format_diff(diff_devices([old], [current]))
    assert "\x1b" not in text
    assert "MAC address changed" in text
    assert "This may be a spoof or a replaced device." in text
    assert "Possible spoof or replaced device." in text
    assert "Was  aa:aa:aa:aa:aa:aa  Old?Co" in text
    assert "Now  bb:bb:bb:bb:bb:bb  New?Co" in text
    assert text.endswith("1 MAC address changed.")
    assert "\nNew\n" not in text
    assert "\nMissing\n" not in text
    assert "\nChanged\n" not in text


def test_format_diff_shows_cleaned_field_changes_and_ignores_mac_case():
    old = Device("192.168.1.20", "aa:bb:cc:dd:ee:ff", "Dell", "lap\x1btop", [])
    current = Device(
        "192.168.1.23",
        "AA:BB:CC:DD:EE:FF",
        "HP",
        "laptop",
        [Port(22, "tcp", "open", "ssh")],
    )
    text = format_diff(diff_devices([old], [current]))
    assert "\x1b" not in text
    assert text == (
        "Changes since your saved snapshot\n"
        "\n"
        "Changed\n"
        "A detail changed on these devices.\n"
        "\n"
        "laptop (192.168.1.23)\n"
        "\n"
        "IP address  was 192.168.1.20, now 192.168.1.23\n"
        "Name        was lap?top, now laptop\n"
        "Maker       was Dell, now HP\n"
        "Ports       was none reported, now 22/tcp open (ssh)\n"
        "\n"
        "1 changed device."
    )


def test_format_diff_says_when_a_change_cleans_to_the_same_text():
    old = Device("192.168.1.1", "aa:aa:aa:aa:aa:aa", hostname="a\x1b")
    current = Device("192.168.1.1", "aa:aa:aa:aa:aa:aa", hostname="a?")
    text = format_diff(diff_devices([old], [current]))
    assert "\x1b" not in text
    assert "Details  changed" in text


def test_devices_json_shape_nulls_and_sorted_ports():
    text = format_devices_json(
        [
            Device(
                "192.168.1.10",
                "AA:BB:CC:DD:EE:10",
                "Dell",
                "laptop",
                [Port(80, "tcp", "open", "http"), Port(53, "udp", "open", None)],
            ),
            Device("192.168.1.2", None, "  ", None),
        ]
    )
    assert json.loads(text) == {
        "devices": [
            {
                "hostname": None,
                "ip": "192.168.1.2",
                "mac": None,
                "ports": [],
                "vendor": None,
            },
            {
                "hostname": "laptop",
                "ip": "192.168.1.10",
                "mac": "AA:BB:CC:DD:EE:10",
                "ports": [
                    {"number": 53, "protocol": "udp", "service": None, "state": "open"},
                    {"number": 80, "protocol": "tcp", "service": "http", "state": "open"},
                ],
                "vendor": "Dell",
            },
        ]
    }
    assert text == json.dumps(json.loads(text), indent=2, sort_keys=True, ensure_ascii=True)


@pytest.mark.parametrize(
    ("device", "wrapped", "expected", "snippets", "absent"),
    [
        pytest.param(
            Device("192.168.1.5", 'aa"bb', "v\\endor", 'h"ost\nname'),
            True,
            {"hostname": 'h"ost?name', "mac": 'aa"bb', "vendor": "v\\endor"},
            ('"hostname": "h\\"ost?name"', '"mac": "aa\\"bb"', '"vendor": "v\\\\endor"'),
            ("\nname", "\x1b"),
            id="quotes-backslash-newline",
        ),
        pytest.param(
            Device("10.0.0.1", None, None, '"}, "pwn": true'),
            True,
            {"hostname": '"}, "pwn": true'},
            (),
            (),
            id="injected-json",
        ),
        pytest.param(
            Device(
                "192.168.1.9\x1b[2J",
                None,
                "caf\u00e9",
                "x\x1b[2Jy",
                [Port(80, "tc\x1bp", "open", "ht\x1btp")],
            ),
            False,
            {
                "hostname": "x?[2Jy",
                "ip": "192.168.1.9?[2J",
                "vendor": "caf\u00e9",
                "mac": None,
                "ports": [{"number": 80, "protocol": "tc?p", "service": "ht?tp", "state": "open"}],
            },
            ("\\u00e9",),
            ("\x1b",),
            id="controls-and-non-ascii",
        ),
    ],
)
def test_json_dumps_escapes_device_strings(device, wrapped, expected, snippets, absent):
    text = format_devices_json([device]) if wrapped else format_device_json(device)
    loaded = json.loads(text)
    assert text == json.dumps(loaded, indent=2, sort_keys=True, ensure_ascii=True)
    body = loaded["devices"][0] if wrapped else loaded
    assert set(body) == {"hostname", "ip", "mac", "ports", "vendor"}
    for key, value in expected.items():
        assert body[key] == value
    for snippet in snippets:
        assert snippet in text
    for item in absent:
        assert item not in text
    if "pwn" in (device.hostname or ""):
        assert list(loaded) == ["devices"]
        assert "pwn" not in loaded


@pytest.mark.parametrize(
    ("info", "expected"),
    [
        (
            NetInfo("wlp2s0", "192.168.1.100", "192.168.1.1", "192.168.1.0/24"),
            {
                "address_count": 256,
                "gateway": "192.168.1.1",
                "interface": "wlp2s0",
                "ip": "192.168.1.100",
                "prefix": 24,
                "range_end": "192.168.1.255",
                "range_start": "192.168.1.0",
                "subnet": "192.168.1.0/24",
            },
        ),
        (
            NetInfo("eth0", "10.0.0.5", None, None),
            {
                "address_count": None,
                "gateway": None,
                "interface": "eth0",
                "ip": "10.0.0.5",
                "prefix": None,
                "range_end": None,
                "range_start": None,
                "subnet": None,
            },
        ),
        (
            NetInfo("eth0", "10.0.0.5", "10.0.0.1", "not-a-network"),
            {
                "address_count": None,
                "gateway": "10.0.0.1",
                "interface": "eth0",
                "ip": "10.0.0.5",
                "prefix": None,
                "range_end": None,
                "range_start": None,
                "subnet": "not-a-network",
            },
        ),
        (
            NetInfo("eth0", "10.0.0.5", "10.0.0.1", "fe80::/64"),
            {
                "address_count": 2**64,
                "gateway": "10.0.0.1",
                "interface": "eth0",
                "ip": "10.0.0.5",
                "prefix": None,
                "range_end": "fe80::ffff:ffff:ffff:ffff",
                "range_start": "fe80::",
                "subnet": "fe80::/64",
            },
        ),
        (
            NetInfo("eth0\x1b", None, "10.0.0.1", "10.0.0.0/24"),
            {
                "address_count": 256,
                "gateway": "10.0.0.1",
                "interface": "eth0?",
                "ip": None,
                "prefix": None,
                "range_end": "10.0.0.255",
                "range_start": "10.0.0.0",
                "subnet": "10.0.0.0/24",
            },
        ),
    ],
    ids=["prefix", "no-subnet", "bad-subnet", "mixed-version", "no-ip"],
)
def test_whoami_json_matches_the_plain_address(info, expected):
    text = format_whoami_json(info)
    assert "\x1b" not in text
    loaded = json.loads(text)
    assert loaded.pop("wsl_nat") is False
    assert loaded.pop("warning") is None
    assert loaded == expected
    shown = "not available" if expected["ip"] is None else expected["ip"]
    assert f"IP address    {shown}" in format_whoami(info)


def test_diff_json_shape_covers_every_section():
    old = Device("192.168.1.5", "aa:aa:aa:aa:aa:aa", "Old", "printer")
    current = Device("192.168.1.5", "bb:bb:bb:bb:bb:bb", "New\x1b", "phone")
    added = Device("192.168.1.9", None, None, "cam\x1bera")
    text = format_diff_json(diff_devices([old], [current, added]))
    assert "\x1b" not in text
    loaded = json.loads(text)
    assert set(loaded) == {"changed", "has_changes", "mac_changed", "missing", "new"}
    assert loaded["has_changes"] is True
    assert loaded["changed"] == []
    assert loaded["missing"] == []
    assert loaded["new"][0]["hostname"] == "cam?era"
    pair = loaded["mac_changed"][0]
    assert set(pair) == {"before", "after"}
    assert pair["before"]["mac"] == "aa:aa:aa:aa:aa:aa"
    assert pair["after"]["hostname"] == "phone"
    assert pair["after"]["vendor"] == "New?"


def test_diff_json_has_changes_is_false_when_nothing_changed():
    device = Device("192.168.1.1", "aa:aa:aa:aa:aa:aa")
    loaded = json.loads(format_diff_json(diff_devices([device], [device])))
    assert loaded["has_changes"] is False
    assert loaded["new"] == []
    assert loaded["missing"] == []
    assert loaded["changed"] == []
    assert loaded["mac_changed"] == []


def test_format_ports_explains_open_ports_and_skips_the_rest():
    device = Device(
        "192.168.1.1",
        None,
        "TP-Link",
        "router.lan",
        [
            Port(23, "tcp", "open", "telnet"),
            Port(443, "tcp", "filtered"),
            Port(53, "tcp", "open", "domain"),
        ],
    )
    text = format_ports(device, notes_for_ports(device.ports))
    assert "443" not in text
    assert "filtered" not in text
    assert "23/tcp  Telnet  risk: high" in text
    assert "Unencrypted remote login" in text
    assert "53/tcp  DNS  risk: low" in text
    assert "Name lookups" in text
    assert text.startswith("Open ports on router.lan (192.168.1.1)")
    assert "2 open ports." in text
    assert text.endswith("Low means this is normal on a home device.")


def test_format_ports_says_when_nothing_is_open():
    device = Device("192.168.1.20", None, None, None, [])
    text = format_ports(device, [])
    assert text.startswith("Open ports on 192.168.1.20")
    assert "No open ports were found." in text
    assert "risk:" not in text


def test_ports_json_cleans_device_strings_and_sorts():
    device = Device(
        "192.168.1.9\x1b[2J",
        None,
        None,
        "x\x1b[2Jy",
        [
            Port(80, "tc\x1bp", "open", "ht\x1btp"),
            Port(22, "tcp", "open", "ssh"),
        ],
    )
    text = format_ports_json(device, notes_for_ports(device.ports))
    assert "\x1b" not in text
    loaded = json.loads(text)
    assert text == json.dumps(loaded, indent=2, sort_keys=True, ensure_ascii=True)
    assert loaded["hostname"] == "x?[2Jy"
    assert loaded["ip"] == "192.168.1.9?[2J"
    assert [port["number"] for port in loaded["ports"]] == [22, 80]
    assert loaded["ports"][1]["protocol"] == "tc?p"
    assert loaded["ports"][1]["service"] == "ht?tp"
    assert loaded["ports"][1]["name"] == "ht?tp"
    assert loaded["ports"][0]["name"] == "SSH"
    assert loaded["ports"][0]["risk"] == "medium"
    assert set(loaded["ports"][0]) == {
        "name",
        "note",
        "number",
        "protocol",
        "risk",
        "service",
        "state",
    }


def test_format_services_shows_product_and_version():
    device = Device(
        "192.168.1.1",
        None,
        None,
        "router.lan",
        [
            Port(22, "tcp", "open", "ssh", "Dropbear sshd", "2022.83"),
            Port(80, "tcp", "open", "http", "lighttpd", None),
            Port(23, "tcp", "closed", "telnet"),
        ],
    )
    text = format_services(device)
    assert "Dropbear sshd" in text
    assert "2022.83" in text
    assert "lighttpd" in text
    assert "unknown" in text
    assert "23" not in text
    assert "Product is the program." in text
    hostile = format_services(
        Device(
            "10.0.0.1",
            None,
            None,
            "n\x1bame",
            [Port(22, "tcp", "open", "ssh", "Drop\x1bbear", "1\x1b.0")],
        )
    )
    assert "\x1b" not in hostile
    assert "Drop?bear" in hostile
    assert "1?.0" in hostile
    assert "n?ame" in hostile


def test_services_json_nulls_missing_product_and_version():
    device = Device(
        "192.168.1.1",
        None,
        None,
        "  ",
        [Port(80, "tcp", "open", "http", None, None)],
    )
    loaded = json.loads(format_services_json(device))
    assert loaded == {
        "hostname": None,
        "ip": "192.168.1.1",
        "services": [
            {
                "number": 80,
                "product": None,
                "protocol": "tcp",
                "service": "http",
                "state": "open",
                "version": None,
            }
        ],
    }


def test_format_router_plain_http_and_quiet_router():
    reached = RouterCheck(
        "192.168.1.1",
        [
            AdminPage("http://192.168.1.1/", 80, True, True, 200, "Router Login", "lighttpd"),
            AdminPage("https://192.168.1.1/", 443, True, False, 401, None, None),
            AdminPage("http://192.168.1.1:8080/", 8080, False, True, error="timed out"),
        ],
    )
    text = format_router(reached)
    assert "Gateway     192.168.1.1" in text
    assert "Plain HTTP  yes" in text
    assert "not encrypted" in text
    assert "Prefer the HTTPS address" in text
    assert "did not log in" in text
    assert "Not reachable (timed out)." in text
    quiet = RouterCheck(
        "10.0.0.1",
        [AdminPage("http://10.0.0.1/", 80, False, True, error="connection refused")],
    )
    quiet_text = format_router(quiet)
    assert "No admin page answered" in quiet_text
    assert "Do not guess passwords." in quiet_text
    assert "Admin page  not reachable" in quiet_text


def test_router_json_cleans_strings_and_keeps_bools():
    result = RouterCheck(
        "192.168.1.1\x1b",
        [AdminPage("http://gw/\x1b", 80, True, True, 200, "Hi\x1b", None, error=None)],
    )
    text = format_router_json(result)
    assert "\x1b" not in text
    loaded = json.loads(text)
    assert loaded["admin_reachable"] is True
    assert loaded["plain_http_reachable"] is True
    assert loaded["gateway"] == "192.168.1.1?"
    page = loaded["pages"][0]
    assert page["title"] == "Hi?"
    assert page["server"] is None
    assert page["url"] == "http://gw/?"
    assert page["status"] == 200
    assert page["error"] is None
    assert set(page) == {
        "error",
        "plain_http",
        "port",
        "reachable",
        "server",
        "status",
        "title",
        "url",
    }


def test_format_speed_labels_an_estimate():
    result = SpeedResult(
        214.6,
        20_000_000,
        7.0,
        "https://speed.cloudflare.com/__down?bytes=25000000",
        median_mbps=210.0,
        connections=4,
        warmup_s=1.0,
        errors=(),
        wsl=True,
        total_bytes=25_000_000,
    )
    failed = SpeedResult(
        214.6,
        20_000_000,
        7.0,
        "https://speed.cloudflare.com/__down?bytes=25000000",
        connections=4,
        warmup_s=1.0,
        errors=("OSError: boom", "timeout"),
        wsl=True,
    )
    estimate = "Download speed  about 215 Mbps (estimate)\nUsed 4 connections over about 8 seconds."
    assert format_speed(result) == estimate
    assert format_speed(failed) == estimate + "\n2 connections reported an error."


def test_format_speed_json_adds_fields():
    raw = format_speed_json(
        SpeedResult(
            8.0,
            1000,
            0.5,
            "https://example.test/\x1b",
            median_mbps=7.5,
            connections=4,
            warmup_s=1.0,
            errors=("OSError: boom\x1b",),
            wsl=True,
            total_bytes=1500,
        )
    )
    assert "\x1b" not in raw
    assert json.loads(raw) == {
        "bytes": 1000,
        "connections": 4,
        "download_mbps": 8.0,
        "errors": ["OSError: boom?"],
        "median_mbps": 7.5,
        "seconds": 0.5,
        "total_bytes": 1500,
        "url": "https://example.test/?",
        "warmup_s": 1.0,
    }


@pytest.mark.parametrize(
    ("dbm", "percent", "phrase"),
    [
        (-40, None, "Excellent (-40 dBm)"),
        (-50, None, "Excellent (-50 dBm)"),
        (-51, None, "Good (-51 dBm)"),
        (-60, None, "Good (-60 dBm)"),
        (-61, None, "Fair (-61 dBm)"),
        (-70, None, "Fair (-70 dBm)"),
        (-71, None, "Weak (-71 dBm)"),
        (None, 80, "Good (80%)"),
        (None, None, "unknown (install iw to see signal)"),
    ],
)
def test_wifi_signal_words(dbm, percent, phrase):
    """dBm thresholds, then percent, then the iw hint. dBm wins when both exist."""
    info = WifiInfo(
        True,
        interface="wlan0",
        ssid="Home\x1b[2J" if dbm == -60 else "Home",
        signal_dbm=dbm,
        signal_percent=1 if dbm is not None else percent,
        channel=6 if dbm == -60 else None,
        band="2.4 GHz" if dbm == -60 else None,
    )
    text = format_wifi(info)
    signal = next(line for line in text.splitlines() if line.startswith("Signal"))
    assert signal.endswith(phrase)
    if dbm == -60:
        assert "\x1b" not in text and "Home?[2J" in text
        notes = [line for line in text.splitlines() if "shorter range" in line]
        assert len(notes) == 1
        assert "Channel 6" in notes[0] and "2.4 GHz" in notes[0] and "5 GHz" in notes[0]


@pytest.mark.parametrize(
    ("ip", "gateway", "label"),
    [
        ("192.168.1.1", "192.168.1.1", "your router"),
        ("1.1.1.1", "1.1.1.1", "your router"),
        ("1.1.1.1", "192.168.1.1", "Cloudflare (public)"),
        ("2606:4700:4700::1111", None, "Cloudflare (public)"),
        ("8.8.8.8", None, "Google (public)"),
        ("2001:4860:4860::8888", None, "Google (public)"),
        ("9.9.9.9", None, "Quad9 (public)"),
        ("149.112.112.112", None, "Quad9 (public)"),
        ("127.0.0.53", "192.168.1.1", "this computer (local resolver)"),
        ("::1", None, "this computer (local resolver)"),
        ("192.168.1.2", "192.168.1.1", "a device on your network"),
        ("fe80::1", "192.168.1.1", "a device on your network"),
        ("1.2.3.4", "192.168.1.1", "likely your internet provider"),
    ],
)
def test_dns_server_labels(ip, gateway, label):
    local = label.startswith("this computer")
    config = DnsConfig(
        [DnsServer(ip, "resolv.conf")],
        source="resolv.conf",
        uses_systemd_stub=ip == "127.0.0.53",
        upstream=["9.9.9.9"] if local else [],
    )
    lookup = LookupResult("example.com\x1b", True, ("93.184.216.34",), 12.0)
    text = format_dns(config, lookup, gateway)
    assert "\x1b" not in text
    row = next(line for line in text.splitlines() if ip in line.split())
    assert label in row
    if ip == "1.1.1.1" and gateway == "1.1.1.1":
        assert "Cloudflare" not in text
    lookup_lines = [line for line in text.splitlines() if line.startswith("Lookup")]
    assert len(lookup_lines) == 1
    assert "example.com?" in lookup_lines[0] and "93.184.216.34" in lookup_lines[0]
    upstream = [line for line in text.splitlines() if line.startswith("Upstream")]
    if local:
        assert len(upstream) == 1 and "9.9.9.9" in upstream[0] and "Quad9" in upstream[0]
    else:
        assert upstream == []

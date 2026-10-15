"""Plain-text formatters. They never scan and never run system commands."""

import json

import pytest

from homenet.core.baseline import diff_devices, load_baseline
from homenet.core.netinfo import NetInfo
from homenet.core.parser import Device, Port, parse_nmap_xml
from homenet.core.port_notes import notes_for_ports
from homenet.core.router import AdminPage, RouterCheck
from homenet.core.speed import SpeedResult
from homenet.output import (
    format_device,
    format_device_json,
    format_devices,
    format_devices_json,
    format_diff,
    format_diff_json,
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
)

_WHOAMI = """\
This computer on your home network

Interface     wlp2s0
IP address    192.168.1.100/24
Gateway       192.168.1.1
Home network  192.168.1.0/24

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


def test_format_whoami_shows_address_with_prefix():
    info = NetInfo("wlp2s0", "192.168.1.100", "192.168.1.1", "192.168.1.0/24")
    assert format_whoami(info) == _WHOAMI


def test_format_whoami_says_when_the_address_is_missing():
    text = format_whoami(NetInfo("wlp2s0", None, "192.168.1.1", "192.168.1.0/24"))
    assert "IP address    not available" in text
    assert "Home network  192.168.1.0/24" in text
    assert text.endswith("This computer's own IP address was not available.")


def test_format_whoami_keeps_a_bare_address_without_a_subnet():
    text = format_whoami(NetInfo("eth0", "10.0.0.5", None, None))
    assert "IP address    10.0.0.5" in text
    assert "Gateway       not available" in text
    assert "Home network  not available" in text
    assert "/not" not in text


def test_format_whoami_ignores_a_subnet_it_cannot_use():
    bad = format_whoami(NetInfo("eth0", "10.0.0.5", "10.0.0.1", "not-a-network"))
    mixed = format_whoami(NetInfo("eth0", "10.0.0.5", "10.0.0.1", "fe80::/64"))
    assert "IP address    10.0.0.5\n" in bad
    assert "Home network  not-a-network" in bad
    assert "IP address    10.0.0.5\n" in mixed
    assert "10.0.0.5/64" not in mixed


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


def test_format_devices_uses_a_singular_count():
    text = format_devices([Device("192.168.1.20", "AA:BB:CC:DD:EE:20", "HP", "printer")])
    assert text.endswith("1 device found.")
    assert "printer" in text


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


def test_device_strings_replace_control_and_nonprintable_characters():
    """A hostile name or vendor must not be able to drive the terminal."""
    screen = format_devices([Device("192.168.1.5", None, "Ok", "x\x1b[2Jy")])
    assert "\x1b" not in screen
    assert "x?[2Jy" in screen

    title = format_devices([Device("192.168.1.6", None, "Evil\x1b]0;pwn\x07", "ok")])
    assert "\x1b" not in title
    assert "\x07" not in title
    assert "Evil?]0;pwn?" in title

    bare = format_devices([Device("192.168.1.7", None, "a\x00b\x07c\x7fd", "e\x1ff")])
    for char in ("\x00", "\x07", "\x7f", "\x1f"):
        assert char not in bare
    assert "a?b?c?d" in bare
    assert "e?f" in bare

    spaced = format_devices([Device("192.168.1.8", "aa\tbb", "line\r\nmore", "tab\there")])
    assert "\t" not in spaced
    assert "\r" not in spaced
    assert "\nmore" not in spaced
    assert "tab?here" in spaced
    assert "aa?bb" in spaced
    assert "line??more" in spaced

    c1 = format_device(
        Device(
            "192.168.1.9",
            None,
            "c\x9d0;pwn\x9cd",
            "a\x9b[2Jb\x85c",
            [Port(80, "tcp", "open", "ht\x1btp")],
        )
    )
    for char in ("\x1b", "\x9b", "\x9d", "\x9c", "\x85"):
        assert char not in c1
    assert "a?[2Jb?c" in c1
    assert "c?0;pwn?d" in c1
    assert "ht?tp" in c1


def test_detail_title_ports_and_whoami_ip_are_cleaned():
    detail = format_device(
        Device(
            "192.168.1.9\x1b[2J",
            None,
            "Ok",
            "laptop",
            [Port(80, "tc\x1bp", "op\x1ben", "http")],
        )
    )
    assert "\x1b" not in detail
    assert "laptop (192.168.1.9?[2J)" in detail
    assert "tc?p" in detail
    assert "op?en" in detail

    missing_subnet = format_whoami(NetInfo("eth0", "10.0.0.5\x1b[31m", "10.0.0.1", None))
    bad_subnet = format_whoami(NetInfo("eth0", "10.0.0.5\x1b[2J", "10.0.0.1", "nope"))
    assert "\x1b" not in missing_subnet
    assert "\x1b" not in bad_subnet
    assert "10.0.0.5?[31m" in missing_subnet
    assert "10.0.0.5?[2J" in bad_subnet


def test_format_error_cleans_the_message_and_the_hint():
    text = format_error("Could not read eth0\x1b[2J.", "Check wlan0\x1b]0;x\x07.")
    assert "\x1b" not in text
    assert "\x07" not in text
    assert text == "Could not read eth0?[2J.\nFix: Check wlan0?]0;x?."


def test_format_device_accepts_a_parsed_host(load_fixture):
    device = parse_nmap_xml(load_fixture("nmap_ports.xml"))[0]
    text = format_device(device)
    assert text.startswith("router.lan (192.168.1.1)")
    assert "53      tcp       open      domain" in text
    assert "80      tcp       open      http" in text
    assert "443     tcp       filtered  unknown" in text


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


def test_format_diff_uses_the_plural_for_several_mac_changes():
    old = [
        Device("192.168.1.5", "aa:aa:aa:aa:aa:aa"),
        Device("192.168.1.6", "cc:cc:cc:cc:cc:cc"),
    ]
    current = [
        Device("192.168.1.5", "bb:bb:bb:bb:bb:bb"),
        Device("192.168.1.6", "dd:dd:dd:dd:dd:dd"),
    ]
    assert format_diff(diff_devices(old, current)).endswith("2 MAC addresses changed.")


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


def test_whoami_json_uses_null_for_missing_fields():
    text = format_whoami_json(NetInfo("eth0\x1b", None, "10.0.0.1", "10.0.0.0/24"))
    assert "\x1b" not in text
    assert json.loads(text) == {
        "gateway": "10.0.0.1",
        "interface": "eth0?",
        "ip": None,
        "subnet": "10.0.0.0/24",
    }


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


def test_format_speed_uses_megabits():
    result = SpeedResult(8.0, 1_000_000, 1.0, "https://speed.cloudflare.com/__down?bytes=1000000")
    text = format_speed(result)
    assert "Download  8.00 Mb/s" in text
    assert "Sample    1000000 bytes" in text
    assert "Time      1.000 seconds" in text
    assert "not a full speed test" in text
    raw = format_speed_json(SpeedResult(8.0, 1000, 0.5, "https://example.test/\x1b"))
    assert "\x1b" not in raw
    assert json.loads(raw) == {
        "bytes": 1000,
        "download_mbps": 8.0,
        "seconds": 0.5,
        "url": "https://example.test/?",
    }

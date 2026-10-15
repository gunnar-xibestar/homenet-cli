"""Plain-text formatters. They never scan and never run system commands."""

from homenet.core.netinfo import NetInfo
from homenet.core.parser import Device, Port, parse_nmap_xml
from homenet.output import format_device, format_devices, format_error, format_whoami

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


def test_format_device_accepts_a_parsed_host(load_fixture):
    device = parse_nmap_xml(load_fixture("nmap_ports.xml"))[0]
    text = format_device(device)
    assert text.startswith("router.lan (192.168.1.1)")
    assert "53      tcp       open      domain" in text
    assert "80      tcp       open      http" in text
    assert "443     tcp       filtered  unknown" in text

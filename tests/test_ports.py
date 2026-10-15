import pytest

from homenet.core.port_notes import GENERIC_NOTE, RISK_LEVELS, note_for, notes_for_ports
from homenet.core.ports import resolve_local_target, scan_ports, scan_services
from homenet.core.runner import (
    DisallowedFlagError,
    InvalidTargetError,
    ScanResult,
    TargetNotAllowedError,
    build_args,
    check_flags,
)

NET = "192.168.1.0/24"


def fake_scan(load_fixture, name, calls):
    def scan(target, mode, top_ports, **kw):
        # run the real validation/arg building, never nmap itself
        calls.append(
            build_args(
                target, mode, top_ports, local_network=kw["local_network"], force=kw["force"]
            )
        )
        return ScanResult(tuple(calls[-1]), load_fixture(name), "", 0)

    return scan


def test_scan_ports_host(load_fixture):
    calls = []
    devices = scan_ports(
        "192.168.1.1",
        top_ports=20,
        local_network=NET,
        scan=fake_scan(load_fixture, "nmap_ports.xml", calls),
    )
    assert calls == [["nmap", "-sT", "--top-ports", "20", "-T4", "-oX", "-", "192.168.1.1/32"]]
    assert [p.number for p in devices[0].ports] == [53, 80, 443]


def test_scan_ports_defaults_to_subnet(load_fixture):
    calls = []
    scan_ports(local_network=NET, scan=fake_scan(load_fixture, "nmap_ports.xml", calls))
    assert calls[0][-1] == NET and "100" in calls[0]


def test_scan_services_light_only(load_fixture):
    calls = []
    (dev,) = scan_services(
        "192.168.1.1", local_network=NET, scan=fake_scan(load_fixture, "nmap_services.xml", calls)
    )
    args = calls[0]
    assert args[1:4] == ["-sT", "-sV", "--version-light"]
    assert not any(a.startswith("--script") or a in ("-A", "-O") for a in args)
    ssh = dev.ports[0]
    assert (ssh.service, ssh.product, ssh.version) == ("ssh", "Dropbear sshd", "2022.83")
    assert dev.ports[1].product is None


# Both scanners go through resolve_local_target; all targets on scan_ports, one on services.
@pytest.mark.parametrize(
    ("fn", "target"),
    [
        *((scan_ports, t) for t in ("10.0.0.5", "192.168.2.0/24", "172.17.0.1", "8.8.8.8")),
        (scan_ports, "192.168.0.0/16"),
        (scan_services, "8.8.8.8"),
    ],
)
def test_outside_local_subnet_refused(fn, target, load_fixture):
    calls = []
    with pytest.raises(TargetNotAllowedError):
        fn(target, local_network=NET, scan=fake_scan(load_fixture, "nmap_ports.xml", calls))
    assert calls == []


def test_local_network_from_default_route(load_fixture):
    def ip_runner(args):
        return load_fixture("ip_route.json" if args[1] == "route" else "ip_addr.json")

    assert resolve_local_target("192.168.1.7", ip_runner=ip_runner) == ("192.168.1.7/32", NET)
    with pytest.raises(TargetNotAllowedError):  # docker0 bridge is not local
        resolve_local_target("172.17.0.2", ip_runner=ip_runner)
    with pytest.raises(TargetNotAllowedError, match="Could not detect"):
        resolve_local_target(None, ip_runner=lambda a: "[]")
    with pytest.raises(InvalidTargetError):
        resolve_local_target("not-an-ip", local_network=NET)


def test_bad_top_ports_refused(load_fixture):
    with pytest.raises(DisallowedFlagError):
        scan_ports(
            "192.168.1.1",
            top_ports=5000,
            local_network=NET,
            scan=fake_scan(load_fixture, "nmap_ports.xml", []),
        )


def test_runner_allows_light_service():
    check_flags(["-sT", "-sV", "--version-light", "--top-ports", "-oX"])


# ---- port notes ----


def test_known_ports():
    table = {
        (22, "tcp"): ("SSH", "medium"),
        (23, "tcp"): ("Telnet", "high"),
        (80, "tcp"): ("HTTP", "medium"),
        (443, "tcp"): ("HTTPS", "low"),
        (445, "tcp"): ("SMB", "high"),
        (3389, "tcp"): ("RDP", "high"),
        (5900, "tcp"): ("VNC", "high"),
        (1900, "udp"): ("UPnP", "medium"),
        (8080, "tcp"): ("HTTP-alt", "medium"),
    }
    for (port, proto), expected in table.items():
        n = note_for(port, proto)
        assert (n.name, n.risk) == expected and n.note, port


def test_service_name_fallback_and_generic():
    assert note_for(2222, "tcp", "ssh").name == "SSH"
    g = note_for(49152, "tcp", "unknown")
    assert g.note == GENERIC_NOTE and g.risk in RISK_LEVELS


def test_notes_for_open_ports_only(load_fixture):
    from homenet.core.parser import parse_nmap_xml

    (dev,) = parse_nmap_xml(load_fixture("nmap_ports.xml"))
    assert [n.port for n in notes_for_ports(dev.ports)] == [53, 80]  # 443 filtered


def test_all_risks_valid():
    from homenet.core import port_notes

    assert {r for _, r, _ in port_notes._NOTES.values()} <= set(RISK_LEVELS)


def test_scan_services_single_host_only_by_default(load_fixture):
    calls = []
    scan = fake_scan(load_fixture, "nmap_services.xml", calls)
    for target in (None, NET, "192.168.1.0/30"):
        with pytest.raises(InvalidTargetError, match="single device|subnet"):
            scan_services(target, local_network=NET, scan=scan)
    assert calls == []
    scan_services("192.168.1.1/32", local_network=NET, scan=scan)
    scan_services(NET, local_network=NET, scan=scan, allow_subnet=True)
    scan_services(local_network=NET, scan=scan, allow_subnet=True)
    assert [c[-1] for c in calls] == ["192.168.1.1/32", NET, NET]


def test_scan_services_allow_subnet_still_local_only(load_fixture):
    with pytest.raises(TargetNotAllowedError):
        scan_services(
            "10.0.0.0/24",
            local_network=NET,
            allow_subnet=True,
            scan=fake_scan(load_fixture, "nmap_services.xml", []),
        )

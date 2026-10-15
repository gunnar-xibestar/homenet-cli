import json
from datetime import datetime, timezone

import pytest

from homenet.core import baseline as bl
from homenet.core.baseline import (
    SCHEMA_VERSION,
    BaselineError,
    BaselineNotFoundError,
    data_dir,
    default_baseline_path,
    diff_devices,
    load_baseline,
    save_baseline,
)
from homenet.core.parser import Device, Port, parse_nmap_xml

NOW = datetime(2026, 10, 15, 9, 0, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def no_real_home(monkeypatch, tmp_path):
    """Make sure nothing touches the real home dir."""
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))


def test_data_dir(tmp_path):
    assert data_dir({"XDG_DATA_HOME": str(tmp_path)}) == tmp_path / "homenet"
    assert data_dir({}, home=tmp_path) == tmp_path / ".local/share/homenet"
    assert data_dir({"XDG_DATA_HOME": "relative"}, home=tmp_path) == (
        tmp_path / ".local/share/homenet"
    )
    assert default_baseline_path({}, tmp_path).name == "baseline.json"


def test_round_trip(tmp_path, load_fixture):
    devices = parse_nmap_xml(load_fixture("nmap_sn_hosts.xml"))
    devices[0].ports.append(Port(80, "tcp", "open", "http"))
    path = save_baseline(devices, tmp_path / "a" / "b.json", now=NOW)
    data = json.loads(path.read_text())
    assert data["schema_version"] == SCHEMA_VERSION
    assert data["saved_at"] == NOW.isoformat()
    assert load_baseline(path) == devices
    assert [p.name for p in path.parent.iterdir()] == ["b.json"]  # no temp files left


def test_default_path_honors_xdg(tmp_path):
    path = save_baseline([Device("192.168.1.1")])
    assert path == tmp_path / "xdg" / "homenet" / "baseline.json"
    assert load_baseline() == [Device("192.168.1.1")]


def test_atomic_write_keeps_old_file_on_failure(tmp_path, monkeypatch):
    path = save_baseline([Device("192.168.1.1")], tmp_path / "b.json")

    def boom(*a, **k):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(bl.os, "replace", boom)
    with pytest.raises(BaselineError, match="No space"):
        save_baseline([Device("192.168.1.2")], path)
    assert load_baseline(path) == [Device("192.168.1.1")]
    assert [p.name for p in tmp_path.iterdir()] == ["b.json"]


def test_load_fixture_v1(fixtures_dir):
    devices = load_baseline(fixtures_dir / "baseline_v1.json")
    assert len(devices) == 4 and devices[2].ports == [Port(80, "tcp", "open", "http")]


def test_missing_baseline(tmp_path):
    with pytest.raises(BaselineNotFoundError) as ei:
        load_baseline(tmp_path / "nope.json")
    assert "`homenet baseline`" in ei.value.hint


@pytest.mark.parametrize(
    "content",
    [
        "{not json",
        "[]",
        '{"schema_version": 1}',
        '{"schema_version": 99, "devices": []}',
        '{"devices": []}',
        '{"schema_version": 1, "devices": [{"mac": "x"}]}',
        '{"schema_version": 1, "devices": [{"ip": "1", "ports": [{"number": "x"}]}]}',
    ],
)
def test_bad_baselines(tmp_path, content):
    p = tmp_path / "b.json"
    p.write_text(content)
    with pytest.raises(BaselineError):
        load_baseline(p)


def test_diff_against_scan(fixtures_dir, load_fixture):
    old = load_baseline(fixtures_dir / "baseline_v1.json")
    cur = parse_nmap_xml(load_fixture("nmap_sn_hosts.xml"))
    d = diff_devices(old, cur)
    assert sorted(x.ip for x in d.new) == ["192.168.1.42", "192.168.1.77"]
    assert [x.ip for x in d.missing] == ["192.168.1.50"]
    # Pi matched by MAC though its IP changed; laptop (no MAC) matched by IP, unchanged
    assert [(o.ip, c.ip) for o, c in d.changed] == [("192.168.1.20", "192.168.1.23")]
    assert d.has_changes


def test_diff_mac_case_and_ip_fallback():
    old = [Device("192.168.1.5", "AA:BB:CC:DD:EE:FF"), Device("192.168.1.6", None, hostname="a")]
    cur = [
        Device("192.168.1.5", "aa:bb:cc:dd:ee:ff"),
        Device("192.168.1.6", "11:22:33:44:55:66", hostname="a"),
    ]
    d = diff_devices(old, cur)
    assert d.new == [] and d.missing == []
    assert [(o.mac, c.mac) for o, c in d.changed] == [(None, "11:22:33:44:55:66")]


def test_diff_same_ip_different_mac_is_mac_changed():
    old, cur = (
        Device("192.168.1.5", "aa:aa:aa:aa:aa:aa"),
        Device("192.168.1.5", "bb:bb:bb:bb:bb:bb"),
    )
    d = diff_devices([old], [cur])
    assert d.mac_changed == [(old, cur)]
    assert d.new == [] and d.missing == [] and d.changed == [] and d.has_changes


def test_diff_no_changes():
    devs = [Device("192.168.1.1", "aa:aa:aa:aa:aa:aa", ports=[Port(1, "tcp", "open")])]
    assert not diff_devices(devs, list(devs)).has_changes

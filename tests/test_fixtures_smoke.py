"""Every fixture loads, and the subprocess guard blocks real commands.

Parsing details are covered by the module tests (parser, netinfo, checks, ...).
"""

import json
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

FIXTURES = sorted(p.name for p in (Path(__file__).parent / "fixtures").iterdir())


def test_every_fixture_loads(load_fixture):
    for name in FIXTURES:
        text = load_fixture(name)
        assert text.strip(), name
        if name.endswith(".json"):
            json.loads(text)
        elif name.endswith(".xml") and "truncated" not in name:
            ET.fromstring(text)


@pytest.mark.parametrize(
    "call",
    [
        lambda: subprocess.run(["nmap", "-sn", "192.168.1.0/24"]),  # noqa: S603, S607
        lambda: subprocess.Popen(["ping", "-c", "1", "192.168.1.1"]),  # noqa: S603, S607
        lambda: subprocess.check_output(["ip", "-j", "addr"]),  # noqa: S603, S607
    ],
    ids=["run", "Popen", "check_output"],
)
def test_guard_blocks_real_commands(call):
    with pytest.raises(AssertionError, match="real command"):
        call()

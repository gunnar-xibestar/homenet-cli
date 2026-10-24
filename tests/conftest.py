"""Shared fixtures. Tests must never run real nmap/ping/ip commands."""

import json
import subprocess
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES


@pytest.fixture
def load_fixture():
    """Return the text of a file in tests/fixtures."""

    def _load(name: str) -> str:
        return (FIXTURES / name).read_text(encoding="utf-8")

    return _load


@pytest.fixture
def load_json_fixture(load_fixture):
    def _load(name: str):
        return json.loads(load_fixture(name))

    return _load


class RealCommandError(AssertionError):
    pass


def _blocked(*args, **kwargs):
    cmd = args[0] if args else kwargs.get("args")
    raise RealCommandError(
        f"Test tried to run a real command: {cmd!r}. "
        "Use fixtures / mocks instead of nmap, ping or ip."
    )


@pytest.fixture(autouse=True)
def no_real_commands(monkeypatch):
    """Fail any test that tries to spawn a subprocess (nmap, ping, ip, ...)."""
    for name in ("run", "Popen", "call", "check_call", "check_output"):
        monkeypatch.setattr(subprocess, name, _blocked)
    monkeypatch.setattr("os.system", _blocked)


@pytest.fixture(autouse=True)
def no_host_install_marker(monkeypatch, tmp_path):
    """Detection must not read the host's deb marker or treat pytest as frozen."""
    from homenet.core import selfinstall

    monkeypatch.setattr(selfinstall, "DEB_MARKER", tmp_path / "no-install-method")

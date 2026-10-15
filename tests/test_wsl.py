"""WSL detection. Pure helpers; no printing and no real files."""

import pytest

from homenet.core.wsl import in_wsl_nat, is_wsl, wsl_nat_active


@pytest.mark.parametrize(
    ("env", "version", "expected"),
    [
        ({"WSL_DISTRO_NAME": "Ubuntu"}, None, True),
        ({"WSL_DISTRO_NAME": "  Ubuntu  "}, "Linux", True),
        ({"WSL_DISTRO_NAME": ""}, "Linux version 6.1", False),
        ({"WSL_DISTRO_NAME": "   "}, "Linux version 6.1", False),
        ({}, "Linux version 5.15.0-microsoft-standard-WSL2", True),
        ({}, "Linux version 5.15.0-Microsoft-Standard", True),
        ({}, "linux version 6.12.94+", False),
        ({}, None, False),
    ],
)
def test_is_wsl(env, version, expected):
    def read(path):
        if path != "/proc/version":
            raise OSError(path)
        if version is None:
            raise OSError(path)
        return version

    assert is_wsl(env, read) is expected


@pytest.mark.parametrize(
    ("address", "expected"),
    [
        ("172.16.0.1", True),
        ("172.22.240.5", True),
        ("172.31.255.255", True),
        ("172.15.255.255", False),
        ("172.32.0.1", False),
        ("192.168.1.20", False),
        ("10.255.255.254", False),
        ("172.22.240.0/20", True),
        ("172.16.0.0/12", True),
        ("172.17.0.0/16", True),
        ("172.16.0.0/11", False),
        ("192.168.0.0/16", False),
        ("172.22.240.5/20", True),
        (None, False),
        ("", False),
        ("   ", False),
        ("not-an-ip", False),
        ("fe80::1", False),
    ],
)
def test_in_wsl_nat(address, expected):
    assert in_wsl_nat(address) is expected


@pytest.mark.parametrize(
    ("addresses", "env", "version", "expected"),
    [
        (("172.22.240.5", "172.22.240.0/20"), {"WSL_DISTRO_NAME": "Ubuntu"}, None, True),
        (("172.22.240.5", None), {}, "Linux version 5.15-microsoft", True),
        ((None, None), {"WSL_DISTRO_NAME": "Ubuntu"}, None, False),
    ],
    ids=["nat", "proc-version", "no-address"],
)
def test_wsl_nat_active(addresses, env, version, expected):
    def read(path):
        if path != "/proc/version":
            raise OSError(path)
        assert version is not None
        return version

    assert wsl_nat_active(*addresses, environ=env, read_text=read) is expected

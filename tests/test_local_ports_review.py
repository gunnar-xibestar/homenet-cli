import json

import pytest

from homenet.cli import main
from homenet.core.local_ports import Listener, LocalPortsError
from homenet.output import format_local_ports


@pytest.mark.parametrize(
    "argv", [["explain", "devices", "--local"], ["explain", "ports", "--local", "10.0.0.1"]]
)
@pytest.mark.parametrize("json_mode", [False, True])
def test_explain_local_misuse_is_a_friendly_error(argv, json_mode, capsys):
    code = main([*argv, "--json"] if json_mode else argv)
    assert code == 2
    out = capsys.readouterr()
    assert "Traceback" not in out.out + out.err and "TypeError" not in out.out + out.err
    if json_mode:
        assert set(json.loads(out.err)) == {"error", "fix_hint"}


def test_explain_ports_local_without_ss_is_friendly(monkeypatch, capsys):
    def boom(**_kw):
        raise LocalPortsError("The `ss` command is not installed.", "sudo apt install iproute2")

    monkeypatch.setattr("homenet.core.local_ports.plan_local_ports", boom)
    assert main(["explain", "ports", "--local"]) == 1
    out = capsys.readouterr()
    assert "ss" in out.out + out.err and "Traceback" not in out.out + out.err


def test_ipv6_listener_is_bracketed():
    text = format_local_ports([Listener("tcp", "::", 80), Listener("tcp", "0.0.0.0", 22)])
    assert "[::]:80" in text and "0.0.0.0:22" in text

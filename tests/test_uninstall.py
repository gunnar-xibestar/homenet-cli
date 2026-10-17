"""homenet uninstall. The subprocess is mocked; nothing real is removed."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from homenet.cli import main
from homenet.core import selfinstall
from homenet.core.commands import Command

_DIST = "homenet-cli"


class _Dist:
    def __init__(self, prefix: str) -> None:
        self.metadata = {"Name": _DIST}
        self._prefix = Path(prefix)

    def read_text(self, filename: str) -> str | None:
        assert filename == "direct_url.json"
        return None

    def locate_file(self, path: str) -> Path:
        return self._prefix / "lib" / "site-packages" / path


def _as_venv(monkeypatch, prefix: str) -> None:
    """Make this process look like a pip install inside a virtual environment."""
    monkeypatch.delenv("PIPX_HOME", raising=False)
    monkeypatch.setattr(sys, "prefix", prefix)
    monkeypatch.setattr(sys, "base_prefix", "/usr")
    monkeypatch.setattr(selfinstall, "distribution", lambda name: _Dist(prefix))


def _record(monkeypatch) -> list[tuple[list[str], dict]]:
    calls: list[tuple[list[str], dict]] = []

    def fake_run(argv, **kwargs):
        calls.append((list(argv), kwargs))
        return subprocess.CompletedProcess(list(argv), 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    return calls


def _baseline(monkeypatch, tmp_path) -> Path:
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    path = tmp_path / "xdg" / "homenet" / "baseline.json"
    path.parent.mkdir(parents=True)
    path.write_text("{}\n", encoding="utf-8")
    return path


def test_confirm_decline_runs_nothing(monkeypatch, tmp_path, capsys):
    path = _baseline(monkeypatch, tmp_path)
    calls = _record(monkeypatch)
    _as_venv(monkeypatch, str(tmp_path / "venv"))
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    prompts: list[str] = []

    def answer_no(prompt: str = "") -> str:
        prompts.append(prompt)
        return "n"

    monkeypatch.setattr("builtins.input", answer_no)

    assert main(["uninstall", "--purge"]) == 0

    captured = capsys.readouterr()
    assert calls == []
    assert path.is_file()
    assert path.parent.is_dir()
    assert prompts == ["Uninstall homenet and delete saved data? [y/N] "]
    assert str(path) in captured.out
    assert "Nothing was removed." in captured.out
    assert "Traceback" not in captured.out + captured.err


def test_yes_builds_the_pip_argv(monkeypatch, tmp_path, capsys):
    path = _baseline(monkeypatch, tmp_path)
    calls = _record(monkeypatch)
    _as_venv(monkeypatch, str(tmp_path / "venv"))
    expected = Command(
        (sys.executable, "-m", "pip", "uninstall", "-y", _DIST),
        "uninstall homenet-cli with pip",
    )

    assert main(["uninstall", "--yes"]) == 0

    captured = capsys.readouterr()
    assert len(calls) == 1
    argv, kwargs = calls[0]
    assert argv == list(expected.argv)
    assert kwargs["shell"] is False
    assert kwargs["timeout"] == selfinstall.UNINSTALL_TIMEOUT
    assert expected.display() in captured.out
    assert "kept" in captured.out
    assert str(path) in captured.out
    assert path.is_file()
    assert "[y/N]" not in captured.out
    assert "Traceback" not in captured.out + captured.err


def test_purge_removes_the_data_path(monkeypatch, tmp_path, capsys):
    path = _baseline(monkeypatch, tmp_path)
    calls = _record(monkeypatch)
    _as_venv(monkeypatch, str(tmp_path / "venv"))

    assert main(["uninstall", "--yes", "--purge"]) == 0

    captured = capsys.readouterr()
    assert len(calls) == 1
    assert calls[0][0] == [sys.executable, "-m", "pip", "uninstall", "-y", _DIST]
    assert calls[0][1]["shell"] is False
    assert str(path) in captured.out
    assert str(path.parent) in captured.out
    assert not path.exists()
    assert not path.parent.exists()
    assert "Removed" in captured.out
    assert "Traceback" not in captured.out + captured.err

"""homenet uninstall. The subprocess is mocked; nothing real is removed."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

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
    """Saved data under a fake HOME, so purge cannot see the real home directory."""
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    monkeypatch.setenv("HOME", str(home))
    xdg = home / "xdg"
    monkeypatch.setenv("XDG_DATA_HOME", str(xdg))
    path = xdg / "homenet" / "baseline.json"
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
    assert path.parent.parent.is_dir()
    assert "Removed" in captured.out
    assert "Traceback" not in captured.out + captured.err


def _write_checkout(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    (path / "pyproject.toml").write_text(
        '[project]\nname = "homenet-cli"\nversion = "0.0.0"\n',
        encoding="utf-8",
    )
    (path / "keep.txt").write_text("keep\n", encoding="utf-8")
    return path


def _guard_rmtree(monkeypatch, tmp_path: Path, forbidden: set[str]) -> None:
    """Fail the test if purge tries to delete '/', HOME, or anything outside tmp."""
    real = selfinstall.shutil.rmtree
    root = os.path.realpath("/")
    sandbox = os.path.realpath(tmp_path)

    def wrapped(path, *args, **kwargs):
        resolved = os.path.realpath(path)
        if resolved == root or resolved in forbidden:
            raise AssertionError(f"refusing to delete {path}")
        if os.path.commonpath([resolved, sandbox]) != sandbox:
            raise AssertionError(f"refusing to delete {path}")
        return real(path, *args, **kwargs)

    monkeypatch.setattr(selfinstall.shutil, "rmtree", wrapped)


def _prepare_purge_case(case: str, monkeypatch, tmp_path: Path) -> list[Path]:
    """Build one unsafe tree. Every returned path must still exist after purge."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    if case == "symlinked_checkout":
        outside = _write_checkout(tmp_path / "outside" / "homenet-cli")
        link = home / "homenet-cli"
        link.symlink_to(outside, target_is_directory=True)
        return [link, outside / "keep.txt"]
    if case == "symlink_parent":
        outside = tmp_path / "outside"
        checkout = _write_checkout(outside / "homenet-cli")
        (home / "projects").symlink_to(outside, target_is_directory=True)
        return [home / "projects", checkout / "keep.txt"]
    if case == "outside_home":
        checkout = _write_checkout(tmp_path / "outside" / "homenet-cli")
        return [checkout / "keep.txt"]
    if case == "home_itself":
        # The data directory would be HOME when XDG_DATA_HOME is HOME's parent.
        rooted = tmp_path / "homenet"
        rooted.mkdir()
        (rooted / "keep.txt").write_text("keep\n", encoding="utf-8")
        monkeypatch.setenv("HOME", str(rooted))
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
        return [rooted / "keep.txt"]
    if case == "unset_home":
        bait = tmp_path / "xdg" / "homenet"
        bait.mkdir(parents=True)
        (bait / "keep.txt").write_text("keep\n", encoding="utf-8")
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
        monkeypatch.delenv("HOME", raising=False)
        return [bait / "keep.txt"]
    if case == "xdg_root":
        decoy = home / "homenet"
        decoy.mkdir()
        (decoy / "keep.txt").write_text("keep\n", encoding="utf-8")
        monkeypatch.setenv("XDG_DATA_HOME", "/")
        return [decoy / "keep.txt"]
    if case == "plain_folder":
        folder = home / "homenet-cli"
        folder.mkdir()
        (folder / "keep.txt").write_text("keep\n", encoding="utf-8")
        return [folder / "keep.txt"]
    raise AssertionError(case)


@pytest.mark.parametrize(
    "case",
    [
        "symlinked_checkout",
        "symlink_parent",
        "outside_home",
        "home_itself",
        "unset_home",
        "xdg_root",
        "plain_folder",
    ],
)
def test_purge_does_not_escape(case, monkeypatch, tmp_path, capsys):
    """--purge must not delete through links, parents, or paths outside HOME."""
    real_data = Path.home() / ".local" / "share" / "homenet"
    real_existed = real_data.exists()
    survive = _prepare_purge_case(case, monkeypatch, tmp_path)
    forbidden = {
        os.path.realpath(path.parent if path.name == "keep.txt" else path) for path in survive
    }
    if case == "home_itself":
        forbidden.add(os.path.realpath(tmp_path / "homenet"))
    _guard_rmtree(monkeypatch, tmp_path, forbidden)
    calls = _record(monkeypatch)
    _as_venv(monkeypatch, str(tmp_path / "venv"))
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": "yes")

    assert main(["uninstall", "--yes", "--purge"]) == 0

    captured = capsys.readouterr()
    assert calls and calls[0][0][:4] == [sys.executable, "-m", "pip", "uninstall"]
    for path in survive:
        assert os.path.lexists(path)
        if path.name == "keep.txt":
            assert path.read_text(encoding="utf-8") == "keep\n"
    if case == "symlinked_checkout":
        assert (tmp_path / "home" / "homenet-cli").is_symlink()
    if case == "unset_home":
        assert "HOME is unset or empty, so homenet did not delete any files." in captured.out
    if case == "plain_folder":
        assert "Source checkouts to remove:" not in captured.out
    if real_existed:
        assert real_data.exists()
    assert "Traceback" not in captured.out + captured.err


def test_yes_alone_does_not_delete_checkouts(monkeypatch, tmp_path, capsys):
    path = _baseline(monkeypatch, tmp_path)
    home = path.parents[2]
    checkout = _write_checkout(home / "src" / "homenet-cli")
    calls = _record(monkeypatch)
    _as_venv(monkeypatch, str(tmp_path / "venv"))
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    prompts: list[str] = []
    shown: list[str] = []

    def answer_no(prompt: str = "") -> str:
        shown.append(capsys.readouterr().out)
        prompts.append(prompt)
        return "n"

    monkeypatch.setattr("builtins.input", answer_no)

    assert main(["uninstall", "--yes", "--purge"]) == 0

    captured = capsys.readouterr()
    assert calls[0][0] == [sys.executable, "-m", "pip", "uninstall", "-y", _DIST]
    assert prompts == ["Type yes to delete source checkouts: "]
    listed = shown[0]
    assert "Data to remove:" in listed
    assert "Source checkouts to remove:" in listed
    assert str(path) in listed
    assert str(checkout) in listed
    assert "Uninstalled" not in listed
    assert "Source checkouts were kept." in captured.out
    assert not path.exists()
    assert not path.parent.exists()
    assert path.parent.parent.is_dir()
    assert (checkout / "keep.txt").is_file()
    assert "Traceback" not in captured.out + captured.err


def test_typed_yes_deletes_checkout_and_data(monkeypatch, tmp_path, capsys):
    path = _baseline(monkeypatch, tmp_path)
    home = path.parents[2]
    checkout = _write_checkout(home / "src" / "homenet-cli")
    secret = tmp_path / "secret.txt"
    secret.write_text("secret\n", encoding="utf-8")
    (checkout / "linked.txt").symlink_to(secret)
    (path.parent / "linked.txt").symlink_to(secret)
    calls = _record(monkeypatch)
    _as_venv(monkeypatch, str(tmp_path / "venv"))
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    prompts: list[str] = []
    shown: list[str] = []

    def answer_yes(prompt: str = "") -> str:
        shown.append(capsys.readouterr().out)
        prompts.append(prompt)
        return "yes"

    monkeypatch.setattr("builtins.input", answer_yes)

    assert main(["uninstall", "--purge"]) == 0

    captured = capsys.readouterr()
    assert calls[0][0] == [sys.executable, "-m", "pip", "uninstall", "-y", _DIST]
    assert prompts == [
        "Uninstall homenet and delete saved data? [y/N] ",
        "Type yes to delete source checkouts: ",
    ]
    listed = shown[0]
    assert "Data to remove:" in listed
    assert "Source checkouts to remove:" in listed
    assert str(path) in listed
    assert str(checkout) in listed
    assert "Uninstalled" not in listed
    assert shown[1].strip() == ""
    assert "Uninstalled" in captured.out
    assert not path.exists()
    assert not path.parent.exists()
    assert path.parent.parent.is_dir()
    assert not checkout.exists()
    assert secret.is_file()
    assert secret.read_text(encoding="utf-8") == "secret\n"
    assert "Traceback" not in captured.out + captured.err

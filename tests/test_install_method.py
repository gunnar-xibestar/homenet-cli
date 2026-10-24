"""Install-method detection (deb, binary, pip) for uninstall, purge, and explain.

Everything happens under ``tmp_path``. Deletion is real only inside it.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from homenet.cli import main
from homenet.core import selfinstall


def _home(monkeypatch, tmp_path: Path) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_DATA_HOME", str(home / "xdg"))
    return home


def _deb(monkeypatch, tmp_path: Path, content: str = "deb\n") -> Path:
    marker = tmp_path / "usr-lib-homenet" / "install-method"
    marker.parent.mkdir(parents=True)
    marker.write_text(content, encoding="utf-8")
    monkeypatch.setattr(selfinstall, "DEB_MARKER", marker)
    return marker


def _binary(monkeypatch, home: Path) -> Path:
    exe = home / ".local" / "bin" / "homenet"
    exe.parent.mkdir(parents=True)
    exe.write_bytes(b"\x7fELF fake")
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(exe))
    return exe


def _no_commands(monkeypatch) -> list:
    calls: list = []

    def fake(cmd, timeout):
        calls.append(cmd)
        raise AssertionError(f"no command may run: {cmd!r}")

    monkeypatch.setattr(selfinstall, "run_command", fake)
    return calls


@pytest.mark.parametrize(
    ("content", "expected"),
    [("deb", True), ("  deb\n", True), ("pip", False), ("debian", False), ("", False)],
)
def test_deb_marker_content(content, expected, tmp_path):
    marker = tmp_path / "install-method"
    marker.write_text(content, encoding="utf-8")
    assert selfinstall.is_deb_install(marker) is expected


def test_deb_marker_absent(tmp_path):
    assert selfinstall.is_deb_install(tmp_path / "missing") is False
    info = selfinstall.detect_install(marker=tmp_path / "missing", frozen=False)
    assert info.kind != selfinstall.KIND_DEB


def test_detect_deb(tmp_path):
    marker = tmp_path / "install-method"
    marker.write_text("deb\n", encoding="utf-8")
    info = selfinstall.detect_install(marker=marker)
    assert info.kind == selfinstall.KIND_DEB
    assert info.command is None
    assert "sudo apt remove homenet" in info.hint


def test_deb_uninstall_text(monkeypatch, tmp_path, capsys):
    home = _home(monkeypatch, tmp_path)
    _deb(monkeypatch, tmp_path)
    calls = _no_commands(monkeypatch)
    data = home / "xdg" / "homenet" / "baseline.json"
    data.parent.mkdir(parents=True)
    data.write_text("{}\n", encoding="utf-8")

    assert main(["uninstall", "--yes", "--purge"]) == 0

    out = capsys.readouterr().out
    assert "system package" in out
    assert "Fix: Remove it with `sudo apt remove homenet`." in out
    assert calls == []
    assert data.is_file()


def test_deb_uninstall_json(monkeypatch, tmp_path, capsys):
    _home(monkeypatch, tmp_path)
    _deb(monkeypatch, tmp_path)
    _no_commands(monkeypatch)

    assert main(["uninstall", "--json"]) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["install"] == "deb"
    assert payload["uninstalled"] is False
    assert payload["removed_paths"] == []
    assert payload["binary"] is None
    assert "sudo apt remove homenet" in payload["fix_hint"]
    assert "system package" in payload["message"]


def test_detect_binary(monkeypatch, tmp_path):
    home = _home(monkeypatch, tmp_path)
    exe = _binary(monkeypatch, home)
    info = selfinstall.detect_install()
    assert info.kind == selfinstall.KIND_BINARY
    assert info.command is None
    assert info.binary == exe.resolve()


def test_frozen_outside_local_bin_is_not_binary(monkeypatch, tmp_path):
    _home(monkeypatch, tmp_path)
    other = tmp_path / "opt" / "homenet"
    other.parent.mkdir()
    other.write_bytes(b"x")
    info = selfinstall.detect_install(executable=str(other), frozen=True)
    assert info.kind != selfinstall.KIND_BINARY


def test_not_frozen_is_not_binary(monkeypatch, tmp_path):
    home = _home(monkeypatch, tmp_path)
    exe = _binary(monkeypatch, home)
    info = selfinstall.detect_install(executable=str(exe), frozen=False)
    assert info.kind != selfinstall.KIND_BINARY


def test_binary_uninstall_removes_only_its_file(monkeypatch, tmp_path, capsys):
    home = _home(monkeypatch, tmp_path)
    exe = _binary(monkeypatch, home)
    neighbor = exe.parent / "other-tool"
    neighbor.write_text("keep\n", encoding="utf-8")
    data = home / "xdg" / "homenet" / "baseline.json"
    data.parent.mkdir(parents=True)
    data.write_text("{}\n", encoding="utf-8")
    calls = _no_commands(monkeypatch)

    assert main(["uninstall", "--yes"]) == 0

    out = capsys.readouterr().out
    assert calls == []
    assert not exe.exists()
    assert neighbor.read_text(encoding="utf-8") == "keep\n"
    assert data.is_file()
    assert f"Removed {exe}." in out


def test_binary_uninstall_decline_keeps_file(monkeypatch, tmp_path, capsys):
    home = _home(monkeypatch, tmp_path)
    exe = _binary(monkeypatch, home)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": "n")

    assert main(["uninstall"]) == 0

    assert exe.is_file()
    assert "Nothing was removed." in capsys.readouterr().out


def test_binary_refuses_outside_local_bin(monkeypatch, tmp_path):
    home = _home(monkeypatch, tmp_path)
    elsewhere = home / "bin" / "homenet"
    elsewhere.parent.mkdir()
    elsewhere.write_bytes(b"x")
    with pytest.raises(selfinstall.SelfInstallError):
        selfinstall.remove_binary(elsewhere, home=home)
    outside = tmp_path / "homenet"
    outside.write_bytes(b"x")
    with pytest.raises(selfinstall.SelfInstallError):
        selfinstall.remove_binary(outside, home=home)
    assert elsewhere.is_file() and outside.is_file()


def test_binary_refuses_symlink(monkeypatch, tmp_path):
    home = _home(monkeypatch, tmp_path)
    target = tmp_path / "victim"
    target.write_text("keep\n", encoding="utf-8")
    bindir = home / ".local" / "bin"
    bindir.mkdir(parents=True)
    link = bindir / "homenet"
    link.symlink_to(target)
    with pytest.raises(selfinstall.SelfInstallError):
        selfinstall.remove_binary(link, home=home)
    assert link.is_symlink()
    assert target.read_text(encoding="utf-8") == "keep\n"


def test_binary_refuses_symlinked_bin_dir(monkeypatch, tmp_path):
    home = _home(monkeypatch, tmp_path)
    real = tmp_path / "realbin"
    real.mkdir()
    exe = real / "homenet"
    exe.write_bytes(b"x")
    (home / ".local").mkdir()
    (home / ".local" / "bin").symlink_to(real, target_is_directory=True)
    with pytest.raises(selfinstall.SelfInstallError):
        selfinstall.remove_binary(home / ".local" / "bin" / "homenet", home=home)
    assert exe.is_file()


def test_binary_uninstall_cli_refuses_symlinked_executable(monkeypatch, tmp_path, capsys):
    home = _home(monkeypatch, tmp_path)
    exe = _binary(monkeypatch, home)
    # Detected install, then swapped for a link before removal.
    info = selfinstall.detect_install()
    exe.unlink()
    victim = tmp_path / "victim"
    victim.write_text("keep\n", encoding="utf-8")
    exe.symlink_to(victim)
    monkeypatch.setattr(selfinstall, "detect_install", lambda **kw: info)

    assert main(["uninstall", "--yes"]) == 1

    assert exe.is_symlink()
    assert victim.read_text(encoding="utf-8") == "keep\n"
    assert "Fix:" in capsys.readouterr().out


def test_purge_with_binary_adds_only_that_path(monkeypatch, tmp_path, capsys):
    home = _home(monkeypatch, tmp_path)
    exe = _binary(monkeypatch, home)
    neighbor = exe.parent / "other-tool"
    neighbor.write_text("keep\n", encoding="utf-8")
    data = home / "xdg" / "homenet" / "baseline.json"
    data.parent.mkdir(parents=True)
    data.write_text("{}\n", encoding="utf-8")
    _no_commands(monkeypatch)

    assert main(["uninstall", "--yes", "--purge", "--json"]) == 0

    payload = json.loads(capsys.readouterr().out)
    assert sorted(payload["removed_paths"]) == sorted(
        [str(data), str(data.parent), str(exe.resolve())]
    )
    assert payload["binary"] == str(exe.resolve())
    assert not exe.exists() and not data.exists()
    assert neighbor.is_file()
    assert (home / ".local" / "bin").is_dir()


def _guard_no_planning(monkeypatch) -> None:
    def boom(*args, **kwargs):
        raise AssertionError("purge must refuse before planning")

    monkeypatch.setattr(selfinstall, "plan_purge", boom)
    monkeypatch.setattr(selfinstall, "detect_install", boom)
    monkeypatch.setattr(selfinstall, "remove_data_dir", boom)
    monkeypatch.setattr(selfinstall, "remove_binary", boom)


@pytest.mark.parametrize("case", ["root", "symlink_to_root", "empty", "unset", "spaces"])
def test_purge_refuses_bad_home(case, monkeypatch, tmp_path, capsys):
    if case == "root":
        monkeypatch.setenv("HOME", "/")
    elif case == "symlink_to_root":
        link = tmp_path / "rootlink"
        link.symlink_to("/", target_is_directory=True)
        monkeypatch.setenv("HOME", str(link))
    elif case == "empty":
        monkeypatch.setenv("HOME", "")
    elif case == "spaces":
        monkeypatch.setenv("HOME", "   ")
    else:
        monkeypatch.delenv("HOME", raising=False)
    _guard_no_planning(monkeypatch)

    assert main(["uninstall", "--yes", "--purge"]) == 1

    out = capsys.readouterr().out
    assert "Fix: Set HOME to your own home folder" in out
    assert "Traceback" not in out


def test_purge_refuses_bad_home_json(monkeypatch, capsys):
    monkeypatch.setenv("HOME", "/")
    _guard_no_planning(monkeypatch)
    assert main(["uninstall", "--yes", "--purge", "--json"]) == 1
    err = json.loads(capsys.readouterr().err)
    assert set(err) == {"error", "fix_hint"}
    assert "root folder" in err["error"]


def test_explain_deb(monkeypatch, tmp_path, capsys):
    _home(monkeypatch, tmp_path)
    _deb(monkeypatch, tmp_path)
    assert main(["explain", "uninstall"]) == 0
    out = capsys.readouterr().out
    assert "$ " not in out
    assert "sudo apt remove homenet" in out

    assert main(["explain", "uninstall", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["commands"] == []
    assert "sudo apt remove homenet" in payload["fix_hint"]


def test_explain_binary(monkeypatch, tmp_path, capsys):
    home = _home(monkeypatch, tmp_path)
    exe = _binary(monkeypatch, home)
    assert main(["explain", "uninstall"]) == 0
    out = capsys.readouterr().out
    assert "$ " not in out
    assert str(exe.resolve()) in out
    assert exe.is_file()

    assert main(["explain", "uninstall", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["commands"] == []
    assert str(exe.resolve()) in payload["note"]


def test_explain_pip(monkeypatch, tmp_path, capsys):
    _home(monkeypatch, tmp_path)
    prefix = tmp_path / "venv"

    class _Dist:
        def read_text(self, name):
            return None

        def locate_file(self, path):
            return prefix / "lib" / "site-packages" / path

    monkeypatch.delenv("PIPX_HOME", raising=False)
    monkeypatch.setattr(sys, "prefix", str(prefix))
    monkeypatch.setattr(sys, "base_prefix", "/usr")
    monkeypatch.setattr(selfinstall, "_user_site", lambda: None)
    monkeypatch.setattr(selfinstall, "distribution", lambda name: _Dist())

    assert main(["explain", "uninstall"]) == 0
    out = capsys.readouterr().out
    assert "pip uninstall -y homenet-cli" in out

    assert main(["explain", "uninstall", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    (cmd,) = payload["commands"]
    assert cmd["argv"][-4:] == ["pip", "uninstall", "-y", "homenet-cli"]
    assert "note" not in payload
    assert os.path.isabs(cmd["argv"][0])

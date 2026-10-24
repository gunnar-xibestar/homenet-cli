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
    [
        ("deb", True),
        ("  deb\n", True),
        ("pip", False),
        ("debian", False),
        ("", False),
        (None, False),
    ],
)
def test_deb_marker_content(content, expected, tmp_path):
    """Only a marker whose stripped content is exactly ``deb`` counts. None is absent."""
    marker = tmp_path / "install-method"
    if content is not None:
        marker.write_text(content, encoding="utf-8")
    assert selfinstall.is_deb_install(marker) is expected
    info = selfinstall.detect_install(marker=marker, frozen=False)
    assert (info.kind == selfinstall.KIND_DEB) is expected
    if expected:
        assert info.command is None
        assert "sudo apt remove homenet" in info.hint


@pytest.mark.parametrize("as_json", [False, True])
def test_deb_uninstall_hint(as_json, monkeypatch, tmp_path, capsys):
    home = _home(monkeypatch, tmp_path)
    _deb(monkeypatch, tmp_path)
    calls = _no_commands(monkeypatch)
    data = home / "xdg" / "homenet" / "baseline.json"
    data.parent.mkdir(parents=True)
    data.write_text("{}\n", encoding="utf-8")
    argv = ["uninstall", "--yes", "--purge"] + (["--json"] if as_json else [])

    assert main(argv) == 0

    out = capsys.readouterr().out
    assert calls == []
    assert data.is_file()
    if as_json:
        payload = json.loads(out)
        assert payload["install"] == "deb"
        assert payload["uninstalled"] is False
        assert payload["removed_paths"] == []
        assert payload["binary"] is None
        assert "sudo apt remove homenet" in payload["fix_hint"]
        assert "system package" in payload["message"]
    else:
        assert "system package" in out
        assert "Fix: Remove it with `sudo apt remove homenet`." in out


@pytest.mark.parametrize(
    ("case", "expected"),
    [("frozen_in_local_bin", True), ("frozen_outside", False), ("not_frozen", False)],
)
def test_detect_binary(case, expected, monkeypatch, tmp_path):
    home = _home(monkeypatch, tmp_path)
    exe = _binary(monkeypatch, home)
    if case == "frozen_outside":
        exe = tmp_path / "opt" / "homenet"
        exe.parent.mkdir()
        exe.write_bytes(b"x")
    info = selfinstall.detect_install(executable=str(exe), frozen=case != "not_frozen")
    assert (info.kind == selfinstall.KIND_BINARY) is expected
    if expected:
        assert info.command is None
        assert info.binary == exe.resolve()
        st = os.lstat(exe)
        assert info.binary_identity == (st.st_dev, st.st_ino)


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


def _identity(path: Path) -> tuple[int, int]:
    st = os.lstat(path)
    return st.st_dev, st.st_ino


@pytest.mark.parametrize(
    "case",
    [
        "home_bin",
        "outside_home",
        "symlink_file",
        "symlinked_bin_dir",
        "symlinked_local_dir",
        "swapped_file",
    ],
)
def test_binary_removal_refuses(case, monkeypatch, tmp_path):
    """Only the detected regular file directly in a real ~/.local/bin is removed."""
    home = _home(monkeypatch, tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = outside / "homenet"
    victim.write_text("keep\n", encoding="utf-8")
    identity = _identity(victim)
    survivors = [victim]
    if case == "home_bin":
        target = home / "bin" / "homenet"
        target.parent.mkdir()
        target.write_text("keep\n", encoding="utf-8")
        identity = _identity(target)
        survivors.append(target)
    elif case == "outside_home":
        target = victim
    elif case == "symlink_file":
        target = home / ".local" / "bin" / "homenet"
        target.parent.mkdir(parents=True)
        target.symlink_to(victim)
    elif case == "symlinked_bin_dir":
        (home / ".local").mkdir()
        (home / ".local" / "bin").symlink_to(outside, target_is_directory=True)
        target = home / ".local" / "bin" / "homenet"
    elif case == "symlinked_local_dir":
        (outside / "bin").mkdir()
        inner = outside / "bin" / "homenet"
        inner.write_text("keep\n", encoding="utf-8")
        identity = _identity(inner)
        survivors.append(inner)
        (home / ".local").symlink_to(outside, target_is_directory=True)
        target = home / ".local" / "bin" / "homenet"
    else:
        target = _binary(monkeypatch, home)
        identity = _identity(target)
        # Write the stranger first, then rename over: the old inode is still
        # alive while the new one is made, so the two cannot share an inode.
        stranger = target.parent / "stranger"
        stranger.write_text("NOT OURS\n", encoding="utf-8")
        os.replace(stranger, target)
        survivors.append(target)
        assert _identity(target) != identity
    texts = {path: path.read_text(encoding="utf-8") for path in survivors}

    with pytest.raises(selfinstall.SelfInstallError) as caught:
        selfinstall.remove_binary(target, home=home, identity=identity)

    assert caught.value.hint
    for path, text in texts.items():
        assert path.read_text(encoding="utf-8") == text
    if case == "symlink_file":
        assert target.is_symlink()


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
    assert payload["message"] is None
    assert payload["fix_hint"] is None
    assert not exe.exists() and not data.exists()
    assert neighbor.is_file()
    assert (home / ".local" / "bin").is_dir()


def _guard_no_planning(monkeypatch) -> list[str]:
    hits: list[str] = []

    def spy(name):
        def boom(*args, **kwargs):
            hits.append(name)
            raise AssertionError(f"purge must refuse before {name}")

        return boom

    for name in ("plan_purge", "detect_install", "remove_data_dir", "remove_binary", "run_command"):
        monkeypatch.setattr(selfinstall, name, spy(name))
    monkeypatch.setattr(os, "walk", spy("os.walk"))
    return hits


@pytest.mark.parametrize(
    "case",
    [
        "root",
        "double_slash",
        "slash_dot",
        "symlink_to_root",
        "empty",
        "unset",
        "spaces",
        "relative",
        "dot_relative",
    ],
)
def test_purge_refuses_bad_home(case, monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "relhome").mkdir()
    values = {
        "root": "/",
        "double_slash": "//",
        "slash_dot": "/./",
        "empty": "",
        "spaces": "   ",
        "relative": "relhome",
        "dot_relative": "./relhome",
    }
    if case == "symlink_to_root":
        link = tmp_path / "rootlink"
        link.symlink_to("/", target_is_directory=True)
        monkeypatch.setenv("HOME", str(link))
    elif case == "unset":
        monkeypatch.delenv("HOME", raising=False)
    else:
        monkeypatch.setenv("HOME", values[case])
    hits = _guard_no_planning(monkeypatch)

    assert main(["uninstall", "--yes", "--purge"]) == 1

    out = capsys.readouterr().out
    assert hits == []
    assert "Fix: Set HOME to your own home folder" in out
    assert "Traceback" not in out


def _as_pip(monkeypatch, tmp_path: Path) -> None:
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


@pytest.mark.parametrize("method", ["deb", "binary", "pip"])
def test_explain_uninstall(method, monkeypatch, tmp_path, capsys):
    home = _home(monkeypatch, tmp_path)
    exe = None
    if method == "deb":
        _deb(monkeypatch, tmp_path)
    elif method == "binary":
        exe = _binary(monkeypatch, home)
    else:
        _as_pip(monkeypatch, tmp_path)

    assert main(["explain", "uninstall"]) == 0
    out = capsys.readouterr().out
    assert main(["explain", "uninstall", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)

    if method == "pip":
        assert "pip uninstall -y homenet-cli" in out
        (cmd,) = payload["commands"]
        assert cmd["argv"][-4:] == ["pip", "uninstall", "-y", "homenet-cli"]
        assert os.path.isabs(cmd["argv"][0])
        assert "note" not in payload
        return
    assert "$ " not in out
    assert payload["commands"] == []
    if method == "deb":
        assert "sudo apt remove homenet" in out
        assert "sudo apt remove homenet" in payload["fix_hint"]
    else:
        assert str(exe.resolve()) in out
        assert str(exe.resolve()) in payload["note"]
        assert exe.is_file()

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


def _record(monkeypatch, git_status: dict[str, str] | None = None) -> list[tuple[list[str], dict]]:
    """Record commands. Git status text is keyed by the real path of ``-C``."""
    calls: list[tuple[list[str], dict]] = []
    statuses = git_status or {}

    def fake_run(argv, **kwargs):
        calls.append((list(argv), kwargs))
        args = list(argv)
        if args and args[0] == "git":
            cwd = ""
            if "-C" in args:
                cwd = args[args.index("-C") + 1]
            key = os.path.realpath(cwd) if cwd else ""
            if "status" in args:
                return subprocess.CompletedProcess(args, 0, stdout=statuses.get(key, ""), stderr="")
            if "rev-list" in args:
                return subprocess.CompletedProcess(args, 0, stdout="0\n", stderr="")
            if "stash" in args:
                return subprocess.CompletedProcess(args, 0, stdout="", stderr="")
            return subprocess.CompletedProcess(args, 1, stdout="", stderr="")
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    return calls


def _pip_argv(calls: list[tuple[list[str], dict]]) -> list[str]:
    for argv, _kwargs in calls:
        if argv[:4] == [sys.executable, "-m", "pip", "uninstall"]:
            return argv
    raise AssertionError(calls)


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


def _safe_git(checkout: Path) -> None:
    """A real .git directory whose config does not run a command."""
    git_dir = checkout / ".git"
    git_dir.mkdir()
    (git_dir / "config").write_text("[core]\n\trepositoryformatversion = 0\n", encoding="utf-8")


def _filter_checkout(home: Path, config: str, worktree: str | None = None) -> list[Path]:
    """A checkout whose clean filter would run ``touch PWNED`` if git started."""
    checkout = _write_checkout(home / "homenet-cli")
    git_dir = checkout / ".git"
    git_dir.mkdir()
    (git_dir / "config").write_text(config, encoding="utf-8")
    if worktree is not None:
        (git_dir / "config.worktree").write_text(worktree, encoding="utf-8")
    info = git_dir / "info"
    info.mkdir()
    (info / "attributes").write_text("* filter=evil\n", encoding="utf-8")
    (checkout / "dirty.txt").write_text("changed\n", encoding="utf-8")
    return [checkout, checkout / "keep.txt", checkout / "dirty.txt"]


def _guard_deletes(monkeypatch, tmp_path: Path, forbidden: set[str]) -> None:
    """Fail the test if an absolute delete hits '/', a forbidden path, or outside tmp.

    Deletes through a directory fd use a relative name and are not re-resolved here.
    """
    real_unlink = os.unlink
    real_rmdir = os.rmdir
    root = os.path.realpath("/")
    sandbox = os.path.realpath(tmp_path)

    def check(path: str | os.PathLike[str]) -> None:
        text = os.fspath(path)
        if not os.path.isabs(text):
            return
        resolved = os.path.realpath(text)
        if resolved == root or resolved in forbidden:
            raise AssertionError(f"refusing to delete {path}")
        if os.path.commonpath([resolved, sandbox]) != sandbox:
            raise AssertionError(f"refusing to delete {path}")

    def wrapped_unlink(path, *args, **kwargs):
        check(path)
        return real_unlink(path, *args, **kwargs)

    def wrapped_rmdir(path, *args, **kwargs):
        check(path)
        return real_rmdir(path, *args, **kwargs)

    monkeypatch.setattr(os, "unlink", wrapped_unlink)
    monkeypatch.setattr(os, "remove", wrapped_unlink)
    monkeypatch.setattr(os, "rmdir", wrapped_rmdir)


def _libc():
    """The C library already loaded in this process. Does not search the disk."""
    import ctypes

    return ctypes.CDLL("libc.so.6", use_errno=True)


def _bind_mount(source: Path, target: Path) -> None:
    """Bind-mount ``source`` on ``target``, or skip when this process cannot."""
    import ctypes
    import errno

    libc = _libc()
    libc.mount.argtypes = [
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_ulong,
        ctypes.c_void_p,
    ]
    libc.mount.restype = ctypes.c_int
    if libc.mount(os.fspath(source).encode(), os.fspath(target).encode(), None, 4096, None) == 0:
        return
    if ctypes.get_errno() in {errno.EPERM, errno.EACCES}:
        pytest.skip("bind mount is not permitted")
    pytest.skip(f"bind mount is not permitted ({ctypes.get_errno()})")


def _umount(target: Path) -> None:
    import ctypes

    libc = _libc()
    libc.umount.argtypes = [ctypes.c_char_p]
    libc.umount.restype = ctypes.c_int
    libc.umount(os.fspath(target).encode())


def _prepare_purge_case(case: str, monkeypatch, tmp_path: Path, mounted: list[Path]) -> list[Path]:
    """Build one unsafe tree. Every returned path must still exist after purge."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
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
    if case == "symlinked_data_dir":
        outside = tmp_path / "outside-data"
        outside.mkdir()
        (outside / "baseline.json").write_text("{}\n", encoding="utf-8")
        (outside / "notes.txt").write_text("keep\n", encoding="utf-8")
        parent = home / "xdg"
        parent.mkdir()
        (parent / "homenet").symlink_to(outside, target_is_directory=True)
        monkeypatch.setenv("XDG_DATA_HOME", str(parent))
        return [parent / "homenet", outside / "baseline.json", outside / "notes.txt"]
    if case == "symlinked_share":
        outside = tmp_path / "outside-share"
        data = outside / "homenet"
        data.mkdir(parents=True)
        (data / "baseline.json").write_text("{}\n", encoding="utf-8")
        (data / "notes.txt").write_text("keep\n", encoding="utf-8")
        local = home / ".local"
        local.mkdir()
        (local / "share").symlink_to(outside, target_is_directory=True)
        return [local / "share", data / "baseline.json", data / "notes.txt"]
    if case == "inner_symlink":
        checkout = _write_checkout(home / "src" / "homenet-cli")
        _safe_git(checkout)
        secret = tmp_path / "secret.txt"
        secret.write_text("keep\n", encoding="utf-8")
        (checkout / "link.txt").symlink_to(secret)
        return [secret]
    if case == "foreign_file":
        monkeypatch.setenv("XDG_DATA_HOME", str(home / "xdg"))
        data = home / "xdg" / "homenet"
        data.mkdir(parents=True)
        (data / "baseline.json").write_text("{}\n", encoding="utf-8")
        (data / "notes.txt").write_text("keep\n", encoding="utf-8")
        return [data, data / "notes.txt"]
    if case == "xdg_inside_home":
        monkeypatch.setenv("XDG_DATA_HOME", str(home / "projects"))
        data = home / "projects" / "homenet"
        (data / "pkg").mkdir(parents=True)
        (data / "pkg" / "app.py").write_text("print('hi')\n", encoding="utf-8")
        (data / "notes.txt").write_text("keep\n", encoding="utf-8")
        (data / "baseline.json").write_text("{}\n", encoding="utf-8")
        return [data, data / "notes.txt", data / "pkg" / "app.py"]
    if case == "monorepo":
        checkout = _write_checkout(home / "homenet-cli")
        _safe_git(checkout)
        team = checkout / "other-team"
        team.mkdir()
        (team / "secret.txt").write_text("keep\n", encoding="utf-8")
        return [checkout, team / "secret.txt"]
    if case == "fsmonitor":
        checkout = _write_checkout(home / "homenet-cli")
        git_dir = checkout / ".git"
        git_dir.mkdir()
        (git_dir / "config").write_text("[core]\n\tfsmonitor = touch PWNED\n", encoding="utf-8")
        return [checkout, checkout / "keep.txt"]
    if case == "stash":
        checkout = _write_checkout(home / "homenet-cli")
        _safe_git(checkout)
        refs = checkout / ".git" / "refs"
        refs.mkdir()
        (refs / "stash").write_text("0123456789abcdef0123456789abcdef01234567\n", encoding="utf-8")
        return [checkout, checkout / "keep.txt"]
    if case == "worktree_config":
        return _filter_checkout(
            home,
            "[extensions]\n\tworktreeConfig = true\n",
            '[filter "evil"]\n\tclean = touch PWNED; cat\n',
        )
    if case == "filter_evil":
        return _filter_checkout(home, "[filter.evil]\n\tclean = touch PWNED; cat\n")
    if case == "bind_mount":
        checkout = _write_checkout(home / "homenet-cli")
        _safe_git(checkout)
        payload = tmp_path / "payload"
        payload.mkdir()
        (payload / "secret.txt").write_text("keep\n", encoding="utf-8")
        mount = checkout / "mnt"
        mount.mkdir()
        _bind_mount(payload, mount)
        mounted.append(mount)
        return [checkout, checkout / "keep.txt", mount / "secret.txt", payload / "secret.txt"]
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
        "symlinked_data_dir",
        "symlinked_share",
        "inner_symlink",
        "foreign_file",
        "xdg_inside_home",
        "monorepo",
        "fsmonitor",
        "stash",
        "worktree_config",
        "filter_evil",
        "bind_mount",
    ],
)
def test_purge_does_not_escape(case, monkeypatch, tmp_path, capsys):
    """--purge must not delete through links, parents, or paths outside HOME."""
    real_data = Path.home() / ".local" / "share" / "homenet"
    real_existed = real_data.exists()
    mounted: list[Path] = []
    try:
        survive = _prepare_purge_case(case, monkeypatch, tmp_path, mounted)
        forbidden = {
            os.path.realpath(path.parent if path.name == "keep.txt" else path) for path in survive
        }
        if case == "home_itself":
            forbidden.add(os.path.realpath(tmp_path / "homenet"))
        _guard_deletes(monkeypatch, tmp_path, forbidden)
        statuses: dict[str, str] = {}
        if case == "monorepo":
            checkout = os.path.realpath(tmp_path / "home" / "homenet-cli")
            statuses[checkout] = "?? other-team/secret.txt\n"
        calls = _record(monkeypatch, statuses)
        _as_venv(monkeypatch, str(tmp_path / "venv"))
        monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
        monkeypatch.setattr("builtins.input", lambda prompt="": "yes")

        assert main(["uninstall", "--yes", "--purge"]) == 0

        captured = capsys.readouterr()
        assert _pip_argv(calls)[:4] == [sys.executable, "-m", "pip", "uninstall"]
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
        if case == "inner_symlink":
            assert not (tmp_path / "home" / "src" / "homenet-cli").exists()
            assert (tmp_path / "secret.txt").read_text(encoding="utf-8") == "keep\n"
        if case == "foreign_file":
            data = tmp_path / "home" / "xdg" / "homenet"
            assert data.is_dir()
            assert not (data / "baseline.json").exists()
            assert "notes.txt" in captured.out
            assert "because it still contains" in captured.out
        if case == "xdg_inside_home":
            data = tmp_path / "home" / "projects" / "homenet"
            assert data.is_dir()
            assert (data / "pkg" / "app.py").is_file()
            assert not (data / "baseline.json").exists()
            assert "notes.txt" in captured.out
            assert "pkg" in captured.out
        if case == "monorepo":
            assert "has untracked files" in captured.out
        if case == "fsmonitor":
            assert "has custom git config" in captured.out
            assert not any(argv and argv[0] == "git" for argv, _kwargs in calls)
        if case == "stash":
            assert "has a stash" in captured.out
            assert not any(argv and argv[0] == "git" for argv, _kwargs in calls)
        if case in {"worktree_config", "filter_evil"}:
            assert "has custom git config" in captured.out
            assert not (tmp_path / "home" / "homenet-cli" / "PWNED").exists()
            ran = "\n".join(" ".join(argv) for argv, _kwargs in calls)
            assert not any(argv and argv[0] == "git" for argv, _kwargs in calls)
            assert "touch" not in ran
            assert "PWNED" not in ran
        if case == "bind_mount":
            assert "has a mount inside it" in captured.out
            assert not any(argv and argv[0] == "git" for argv, _kwargs in calls)
        if real_existed:
            assert real_data.exists()
        assert "Traceback" not in captured.out + captured.err
    finally:
        for path in reversed(mounted):
            _umount(path)


def test_yes_alone_does_not_delete_checkouts(monkeypatch, tmp_path, capsys):
    path = _baseline(monkeypatch, tmp_path)
    home = path.parents[2]
    checkout = _write_checkout(home / "src" / "homenet-cli")
    _safe_git(checkout)
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
    assert _pip_argv(calls) == [sys.executable, "-m", "pip", "uninstall", "-y", _DIST]
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
    _safe_git(checkout)
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
    assert _pip_argv(calls) == [sys.executable, "-m", "pip", "uninstall", "-y", _DIST]
    git_calls = [(argv, kwargs) for argv, kwargs in calls if argv and argv[0] == "git"]
    assert git_calls
    git_argv, git_kwargs = git_calls[0]
    assert git_argv[:5] == ["git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null"]
    git_env = git_kwargs["env"]
    assert git_env["GIT_CONFIG_NOSYSTEM"] == "1"
    assert git_env["GIT_CONFIG_GLOBAL"] == "/dev/null"
    assert git_env["GIT_OPTIONAL_LOCKS"] == "0"
    assert git_env["GIT_TERMINAL_PROMPT"] == "0"
    assert sorted(key for key in git_env if key.startswith("GIT_")) == [
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_NOSYSTEM",
        "GIT_OPTIONAL_LOCKS",
        "GIT_TERMINAL_PROMPT",
    ]
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
    assert path.parent.is_dir()
    assert (path.parent / "linked.txt").is_symlink()
    assert "linked.txt" in captured.out
    assert "because it still contains" in captured.out
    assert path.parent.parent.is_dir()
    assert not checkout.exists()
    assert secret.is_file()
    assert secret.read_text(encoding="utf-8") == "secret\n"
    assert "Traceback" not in captured.out + captured.err


@pytest.mark.parametrize("kind", ["eof", "keyboard", "no_tty"])
def test_prompt_keeps_files(kind, monkeypatch, tmp_path, capsys):
    """EOF, Ctrl-C, and a missing terminal keep every file and do not traceback."""
    path = _baseline(monkeypatch, tmp_path)
    checkout = _write_checkout(path.parents[2] / "src" / "homenet-cli")
    _safe_git(checkout)
    _record(monkeypatch)
    _as_venv(monkeypatch, str(tmp_path / "venv"))
    if kind == "no_tty":
        monkeypatch.setattr(sys.stdin, "isatty", lambda: False)

        def refuse_input(prompt: str = "") -> str:
            raise AssertionError(prompt)

        monkeypatch.setattr("builtins.input", refuse_input)
        assert main(["uninstall", "--purge"]) == 1
        captured = capsys.readouterr()
        assert "not an interactive terminal" in captured.out
    else:
        monkeypatch.setattr(sys.stdin, "isatty", lambda: True)

        def interrupt(prompt: str = "") -> str:
            raise EOFError if kind == "eof" else KeyboardInterrupt

        monkeypatch.setattr("builtins.input", interrupt)
        assert main(["uninstall", "--purge"]) == 0
        captured = capsys.readouterr()
        assert "Nothing was removed." in captured.out
    assert path.is_file()
    assert checkout.is_dir()
    assert (checkout / "keep.txt").is_file()
    assert "Traceback" not in captured.out + captured.err

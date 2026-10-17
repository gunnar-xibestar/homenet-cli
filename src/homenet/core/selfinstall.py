"""Detect how this copy of homenet was installed, and uninstall it.

Uses :class:`~homenet.core.commands.Command` and :func:`~homenet.core.commands.run_command`,
so the command hook sees the real argv. Never prints and never calls ``sys.exit``.
Saved data is the baseline path from :mod:`homenet.core.baseline`.

``--purge`` may delete only two kinds of path:

* the homenet data directory (``$XDG_DATA_HOME/homenet`` when that variable is
  an absolute path, otherwise ``~/.local/share/homenet``)
* source checkouts under the home directory

A checkout is a directory named exactly ``homenet-cli`` whose ``pyproject.toml``
has project name ``homenet-cli``. The search is :func:`os.walk` with
``followlinks=False``, starting at ``HOME`` and stopping at
:data:`CHECKOUT_MAX_DEPTH` (the home directory is depth 0). Symbolic links are
not descended into and not deleted. Hidden directories are skipped, except
``~/.local``. Directory names in :data:`SKIP_DIR_NAMES` (``node_modules`` and
similar build or dependency folders) are skipped everywhere. A matched checkout
is not walked into.

A path is deleted only when :func:`os.path.realpath` of it is strictly inside
:func:`os.path.realpath` of ``HOME``. ``/``, the home directory itself, and
anything outside home are refused. When ``HOME`` is unset or empty, nothing
is deleted.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import site
import stat
import subprocess  # noqa: S404 - TimeoutExpired only; the process is run_command
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError
from importlib.metadata import distribution as distribution
from pathlib import Path
from urllib.parse import unquote, urlparse

from homenet.core._text import clean_text
from homenet.core.baseline import BASELINE_FILENAME, data_dir, default_baseline_path
from homenet.core.commands import Command, run_command

DIST_NAME = "homenet-cli"
APT_PACKAGE = "python3-homenet-cli"
UNINSTALL_TIMEOUT = 120.0
GIT_TIMEOUT = 10.0
# Home is depth 0. ~/a/b/c/d/e/homenet-cli is depth 6 and is included.
CHECKOUT_MAX_DEPTH = 6
CHECKOUT_DIR_NAME = "homenet-cli"
# Build and dependency directories. Hidden names are skipped separately,
# except the direct child ~/.local.
SKIP_DIR_NAMES = frozenset(
    {
        "node_modules",
        "__pycache__",
        "site-packages",
        "venv",
        "dist",
        "build",
        "vendor",
    }
)
HOME_UNSET_MESSAGE = (
    "HOME is unset or empty, so homenet did not delete any files. "
    "Set HOME to your home folder if you still want saved data removed."
)

KIND_VENV = "venv"
KIND_PIPX = "pipx"
KIND_USER = "user"
KIND_SYSTEM = "system"
KIND_EDITABLE = "editable"
KIND_UNKNOWN = "unknown"

_AUTOMATIC = frozenset({KIND_VENV, KIND_PIPX, KIND_USER})
_DIST_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*$")


class SelfInstallError(Exception):
    """A refused or failed uninstall. ``hint`` is the beginner-friendly fix."""

    def __init__(self, message: str, hint: str | None = None) -> None:
        super().__init__(message)
        self.hint = hint


@dataclass(frozen=True)
class InstallInfo:
    """How this process's homenet was installed.

    ``command`` is set only for a venv, pipx, or user-site install. System,
    editable, and unknown installs stay ``None`` so nothing is executed.
    """

    kind: str
    distribution: str
    command: Command | None
    message: str
    hint: str | None = None

    @property
    def automatic(self) -> bool:
        return self.command is not None and self.kind in _AUTOMATIC


def _within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except (ValueError, OSError):
        return False
    return True


def _dist_name(dist: object) -> str:
    metadata = getattr(dist, "metadata", None)
    raw = metadata.get("Name") if metadata is not None and hasattr(metadata, "get") else None
    text = clean_text(raw) or DIST_NAME
    if _DIST_NAME.fullmatch(text):
        return text
    return DIST_NAME


def _direct_url(dist: object) -> dict | None:
    read = getattr(dist, "read_text", None)
    if read is None:
        return None
    try:
        raw = read("direct_url.json")
    except (OSError, TypeError, ValueError):
        return None
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _editable_source(direct: dict | None) -> str | None:
    """Source checkout from PEP 610 ``direct_url.json``, when the install is editable."""
    if not direct:
        return None
    info = direct.get("dir_info")
    if not isinstance(info, dict) or not info.get("editable"):
        return None
    url = direct.get("url")
    if not isinstance(url, str) or not url.startswith("file:"):
        return ""
    path = unquote(urlparse(url).path)
    return clean_text(path) or ""


def _site_dir(dist: object) -> Path | None:
    locate = getattr(dist, "locate_file", None)
    if locate is None:
        return None
    try:
        located = locate("")
    except (OSError, TypeError, ValueError):
        return None
    if not located:
        return None
    try:
        return Path(str(located)).resolve()
    except OSError:
        return None


def _in_pipx(prefix: Path, environ: Mapping[str, str]) -> bool:
    """True when ``prefix`` is a pipx venv (``$PIPX_HOME`` or the default path)."""
    roots: list[Path] = []
    raw = environ.get("PIPX_HOME", "").strip()
    if raw:
        roots.append(Path(raw).expanduser())
    roots.append(Path.home() / ".local" / "pipx")
    for root in roots:
        if _within(prefix, root / "venvs"):
            return True
    parts = prefix.parts
    return "pipx" in parts and "venvs" in parts


def _user_site() -> Path | None:
    try:
        raw = site.getusersitepackages()
    except (AttributeError, OSError):
        return None
    if not raw:
        return None
    try:
        return Path(raw).resolve()
    except OSError:
        return None


def _looks_like_system(path: Path, base_prefix: Path) -> bool:
    if _within(path, base_prefix):
        return True
    text = str(path)
    return text.startswith("/usr/") or "/dist-packages" in text


def _pip_command(executable: str, dist_name: str, kind: str) -> Command:
    if kind == KIND_VENV:
        where = "a virtual environment"
    else:
        where = "your user site-packages"
    return Command(
        (executable, "-m", "pip", "uninstall", "-y", dist_name),
        f"uninstall {dist_name} with pip from {where}",
    )


def _manual(kind: str, dist_name: str, source: str | None) -> tuple[str, str]:
    pip = f"`python -m pip uninstall {dist_name}`"
    apt = f"`sudo apt remove {APT_PACKAGE}`"
    root_pip = f"`sudo python -m pip uninstall {dist_name}`"
    if kind == KIND_EDITABLE:
        where = f" at {source}" if source else ""
        return (
            "This copy of homenet is an editable install, so it was not removed.",
            f"From the source checkout{where}, run {pip}.",
        )
    if kind == KIND_SYSTEM:
        return (
            "This copy of homenet was installed for the whole system, so it was not removed.",
            f"If apt installed it, run {apt}. If root pip installed it, run {root_pip}.",
        )
    return (
        "homenet could not tell how this copy was installed, so it was not removed.",
        f"From the environment that installed it, run {pip}. If apt installed it, try {apt}.",
    )


def _classify(
    dist: object,
    *,
    prefix: str,
    base_prefix: str,
    environ: Mapping[str, str],
) -> tuple[str, str | None]:
    """Return ``(kind, editable source)``. Source is None when it is not editable."""
    direct = _direct_url(dist)
    source = _editable_source(direct)
    if source is not None:
        return KIND_EDITABLE, source
    prefix_path = Path(prefix).resolve()
    base_path = Path(base_prefix).resolve()
    if _in_pipx(prefix_path, environ):
        return KIND_PIPX, None
    located = _site_dir(dist)
    user = _user_site()
    in_venv = prefix != base_prefix
    # User site wins over a venv that can see it. A system path is not a venv install.
    if located is not None and user is not None and _within(located, user):
        return KIND_USER, None
    if in_venv and (located is None or _within(located, prefix_path)):
        return KIND_VENV, None
    if located is not None and _looks_like_system(located, base_path):
        return KIND_SYSTEM, None
    if in_venv:
        return KIND_VENV, None
    return KIND_UNKNOWN, None


def detect_install(
    *,
    environ: Mapping[str, str] | None = None,
    prefix: str | None = None,
    base_prefix: str | None = None,
    executable: str | None = None,
) -> InstallInfo:
    """Classify this install. Runs nothing.

    Signals, in order: ``direct_url.json`` editable, the pipx home (env or
    ``~/.local/pipx``), ``sys.prefix`` against ``sys.base_prefix``, then
    :func:`site.getusersitepackages`. Anything else found on the system
    prefix is system/apt. A missing distribution is unknown.
    """
    env = os.environ if environ is None else environ
    prefix = sys.prefix if prefix is None else prefix
    base_prefix = sys.base_prefix if base_prefix is None else base_prefix
    executable = sys.executable if executable is None else executable
    try:
        dist = distribution(DIST_NAME)
    except PackageNotFoundError:
        message, hint = _manual(KIND_UNKNOWN, DIST_NAME, None)
        return InstallInfo(KIND_UNKNOWN, DIST_NAME, None, message, hint)

    dist_name = _dist_name(dist)
    kind, source = _classify(dist, prefix=prefix, base_prefix=base_prefix, environ=env)
    if kind == KIND_PIPX:
        command = Command(("pipx", "uninstall", dist_name), f"uninstall {dist_name} with pipx")
        return InstallInfo(kind, dist_name, command, "")
    if kind in {KIND_VENV, KIND_USER}:
        return InstallInfo(kind, dist_name, _pip_command(executable, dist_name, kind), "")
    message, hint = _manual(kind, dist_name, source)
    return InstallInfo(kind, dist_name, None, message, hint)


def plan_uninstall() -> list[Command]:
    """The uninstall command, or :class:`SelfInstallError` when nothing may run."""
    info = detect_install()
    if info.command is None:
        raise SelfInstallError(info.message, info.hint)
    return [info.command]


def saved_data_paths(
    environ: Mapping[str, str] | None = None, home: Path | None = None
) -> tuple[Path, Path]:
    """Baseline file and its data directory, from the existing path helpers."""
    return default_baseline_path(environ, home), data_dir(environ, home)


@dataclass(frozen=True)
class SourceCheckout:
    """A source checkout that passed the containment checks."""

    path: Path
    warnings: tuple[str, ...]


@dataclass(frozen=True)
class PurgePlan:
    """What ``--purge`` may delete. Paths already passed the containment checks.

    ``blocked`` is set when nothing may be deleted, which is when ``HOME`` is
    unset or empty. ``data_dir`` is the homenet data directory, or None when
    that directory is missing or not safe. ``baseline`` is the snapshot file
    inside it when that file is a real file. ``checkouts`` are source
    directories under the home directory.
    """

    home: Path | None
    data_dir: Path | None
    baseline: Path | None
    checkouts: tuple[SourceCheckout, ...]
    blocked: str | None = None


def _home_from_env(environ: Mapping[str, str], home: Path | None) -> Path | None:
    """The home directory, or None when it is unset or empty."""
    if home is not None:
        text = os.fspath(home).strip()
    else:
        raw = environ.get("HOME")
        text = "" if raw is None else str(raw).strip()
    if not text:
        return None
    return Path(text).expanduser()


def _realpath(path: Path) -> str | None:
    try:
        return os.path.realpath(path)
    except (OSError, ValueError):
        return None


def _same_path(left: Path, right: Path) -> bool:
    left_real = _realpath(left)
    right_real = _realpath(right)
    return bool(left_real) and left_real == right_real


def _contained(path: Path, home: Path) -> bool:
    """True when ``realpath(path)`` is strictly inside ``realpath(home)``."""
    home_real = _realpath(home)
    path_real = _realpath(path)
    if not home_real or not path_real:
        return False
    root = os.path.abspath(os.sep)
    if home_real == root or path_real == root or path_real == home_real:
        return False
    if not os.path.isabs(home_real) or not os.path.isabs(path_real):
        return False
    try:
        return os.path.commonpath([home_real, path_real]) == home_real
    except ValueError:
        return False


def _is_symlink(path: Path) -> bool:
    """True when ``path`` is a symlink. Unreadable paths count as unsafe."""
    try:
        return stat.S_ISLNK(os.lstat(path).st_mode)
    except OSError:
        return True


def _has_symlink_component(path: Path, home: Path) -> bool:
    """True when any component from a child of ``home`` through ``path`` is a symlink."""
    root = Path(os.path.abspath(os.fspath(home)))
    target = Path(os.path.abspath(os.fspath(path)))
    try:
        parts = target.relative_to(root).parts
    except ValueError:
        return True
    current = root
    for index, part in enumerate(parts):
        current = current / part
        last = index == len(parts) - 1
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            return not last
        except OSError:
            return True
        if stat.S_ISLNK(info.st_mode):
            return True
    return False


def _safe_directory(path: Path, home: Path) -> bool:
    """True for a real directory strictly inside ``home``, with no symlink components."""
    if not _contained(path, home) or _has_symlink_component(path, home):
        return False
    try:
        info = os.lstat(path)
    except OSError:
        return False
    return stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)


def _skipped_dirname(name: str, parent_depth: int) -> bool:
    if name in SKIP_DIR_NAMES:
        return True
    if name.startswith("."):
        return not (parent_depth == 0 and name == ".local")
    return False


def _toml_loads():
    """``tomllib.loads`` on 3.11+, ``tomli.loads`` when that package is installed."""
    try:
        import tomllib
    except ModuleNotFoundError:
        try:
            import tomli as tomllib
        except ModuleNotFoundError:
            return None
    return tomllib.loads


def _load_toml(text: str) -> dict | None:
    loads = _toml_loads()
    if loads is None:
        return _project_table_fallback(text)
    try:
        data = loads(text)
    except (UnicodeDecodeError, ValueError, TypeError):
        return None
    return data if isinstance(data, dict) else None


_NAME_LINE = re.compile(r"""^name\s*=\s*(['"])(.*?)\1\s*(?:#.*)?$""")


def _project_table_fallback(text: str) -> dict | None:
    """Read ``[project].name`` when no TOML library is installed."""
    table = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            table = line[1:-1].strip()
            continue
        if table != "project":
            continue
        match = _NAME_LINE.match(line)
        if match:
            return {"project": {"name": match.group(2)}}
    return None


def _project_name(pyproject: Path) -> str | None:
    try:
        text = pyproject.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return None
    data = _load_toml(text)
    if not isinstance(data, dict):
        return None
    project = data.get("project")
    if not isinstance(project, dict):
        return None
    name = project.get("name")
    if not isinstance(name, str):
        return None
    return name.strip() or None


def _is_checkout(path: Path) -> bool:
    """True when ``path`` is a real ``homenet-cli`` checkout, not a symlink."""
    if path.name != CHECKOUT_DIR_NAME or _is_symlink(path):
        return False
    pyproject = path / "pyproject.toml"
    try:
        info = os.lstat(pyproject)
    except OSError:
        return False
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        return False
    return _project_name(pyproject) == DIST_NAME


def find_source_checkouts(home: Path) -> tuple[Path, ...]:
    """Source checkouts strictly inside ``home``.

    Uses :func:`os.walk` with ``followlinks=False``. Does not descend into
    symbolic links, hidden directories other than ``<home>/.local``,
    :data:`SKIP_DIR_NAMES`, or a directory that already matched.
    """
    root = Path(os.path.abspath(os.fspath(home)))
    # os.path.isdir follows a symlink at the start. os.walk still will not
    # descend into symlinks below it (followlinks=False).
    if not os.path.isdir(root):
        return ()
    found: list[Path] = []
    for dirpath, dirnames, _filenames in os.walk(root, topdown=True, followlinks=False):
        current = Path(dirpath)
        try:
            depth = len(current.relative_to(root).parts)
        except ValueError:
            dirnames[:] = []
            continue
        if depth >= CHECKOUT_MAX_DEPTH:
            dirnames[:] = []
            continue
        kept: list[str] = []
        for name in list(dirnames):
            if depth + 1 > CHECKOUT_MAX_DEPTH:
                continue
            child = current / name
            if _is_symlink(child) or _skipped_dirname(name, depth):
                continue
            if name == CHECKOUT_DIR_NAME and _is_checkout(child) and _safe_directory(child, root):
                found.append(child)
                continue
            kept.append(name)
        dirnames[:] = kept
    return tuple(found)


def _has_git_dir(path: Path) -> bool:
    try:
        os.lstat(path / ".git")
    except OSError:
        return False
    return True


class _GitUnavailable(Exception):
    """``git`` is not installed."""


def _git(
    checkout: Path, args: tuple[str, ...], purpose: str
) -> subprocess.CompletedProcess[str] | None:
    """Run git in ``checkout``. None means the command failed. Missing git raises."""
    command = Command(("git", "-C", os.fspath(checkout), *args), purpose)
    try:
        return run_command(command, GIT_TIMEOUT)
    except FileNotFoundError as exc:
        raise _GitUnavailable from exc
    except (subprocess.TimeoutExpired, PermissionError, OSError):
        return None


def _positive_count(text: str) -> bool:
    value = text.strip()
    return value.isdigit() and int(value) > 0


def _checkout_warnings(path: Path) -> tuple[str, ...]:
    """Uncommitted or unpushed work. Empty when git is missing or the tree is clean."""
    if not _has_git_dir(path):
        return ()
    warnings: list[str] = []
    try:
        status = _git(
            path,
            ("status", "--porcelain"),
            "check whether the source checkout has uncommitted changes",
        )
    except _GitUnavailable:
        return ()
    if status is None:
        warnings.append("could not check for uncommitted changes")
    elif status.returncode == 0 and status.stdout.strip():
        warnings.append("uncommitted changes")
    try:
        ahead = _git(
            path,
            ("rev-list", "--count", "@{upstream}..HEAD"),
            "check whether the source checkout has unpushed commits",
        )
    except _GitUnavailable:
        return tuple(warnings)
    if ahead is None:
        warnings.append("could not check for unpushed commits")
        return tuple(warnings)
    if ahead.returncode == 0:
        if _positive_count(ahead.stdout):
            warnings.append("unpushed commits")
        return tuple(warnings)
    try:
        local = _git(
            path,
            ("rev-list", "--count", "HEAD", "--not", "--remotes"),
            "check whether the source checkout has commits that are not on a remote",
        )
    except _GitUnavailable:
        return tuple(warnings)
    if local is not None and local.returncode == 0 and _positive_count(local.stdout):
        warnings.append("unpushed commits")
    return tuple(warnings)


def _planned_data(environ: Mapping[str, str], home: Path) -> tuple[Path | None, Path | None]:
    """The data directory and baseline file, or ``(None, None)`` when unsafe."""
    directory = data_dir(environ, home)
    root_dir = Path(os.path.abspath(os.sep))
    if directory.name != "homenet":
        return None, None
    if _same_path(directory, home) or _same_path(directory, root_dir):
        return None, None
    if _same_path(directory, directory.parent):
        return None, None
    if not _safe_directory(directory, home):
        return None, None
    baseline = directory / BASELINE_FILENAME
    try:
        info = os.lstat(baseline)
    except OSError:
        return directory, None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        return directory, None
    return directory, baseline


def plan_purge(environ: Mapping[str, str] | None = None, home: Path | None = None) -> PurgePlan:
    """List the data directory and source checkouts ``--purge`` may delete.

    Runs nothing except ``git`` status checks for checkouts that are git
    repositories. When ``git`` is missing, those checks are skipped.
    """
    env = os.environ if environ is None else environ
    root = _home_from_env(env, home)
    if root is None:
        return PurgePlan(None, None, None, (), HOME_UNSET_MESSAGE)
    directory, baseline = _planned_data(env, root)
    checkouts = tuple(
        SourceCheckout(path, _checkout_warnings(path)) for path in find_source_checkouts(root)
    )
    return PurgePlan(root, directory, baseline, checkouts, None)


def _reraise_rmtree(func: object, path: object, exc: BaseException) -> None:
    raise exc


def _remove_tree(path: Path) -> None:
    """Delete a real directory. A symlink root is refused before ``rmtree``."""
    if not os.path.isabs(os.fspath(path)):
        raise SelfInstallError(
            f"{path} is not an absolute path, so it was not deleted.",
            "homenet only deletes folders inside your home directory.",
        )
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise SelfInstallError(
            f"Could not delete {path}: {exc.strerror or exc}",
            "Delete that folder yourself if you still want it gone.",
        ) from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise SelfInstallError(
            f"{path} is not a real folder, so it was not deleted.",
            "homenet does not follow symbolic links.",
        )
    try:
        if sys.version_info >= (3, 12):
            shutil.rmtree(path, onexc=_reraise_rmtree)
        else:
            shutil.rmtree(path)
    except OSError as exc:
        raise SelfInstallError(
            f"Could not delete {path}: {exc.strerror or exc}",
            "Delete that folder yourself if you still want it gone.",
        ) from exc


def _refuse_outside(path: Path) -> None:
    raise SelfInstallError(
        f"{path} is outside the home directory or is a symbolic link, so it was not deleted.",
        "homenet only deletes real folders inside your home directory.",
    )


def remove_data_dir(
    path: Path,
    *,
    home: Path,
    environ: Mapping[str, str] | None = None,
) -> None:
    """Delete the homenet data directory after containment and symlink checks.

    ``path`` must be that directory itself (``.../homenet``), never a parent.
    """
    env = os.environ if environ is None else environ
    root = _home_from_env(env, home)
    if root is None:
        raise SelfInstallError(HOME_UNSET_MESSAGE)
    expected = data_dir(env, root)
    not_the_data_dir = (
        path.name != "homenet"
        or not _same_path(path, expected)
        or _same_path(path, expected.parent)
        or _same_path(path, root)
        or _same_path(path, Path(os.path.abspath(os.sep)))
    )
    if not_the_data_dir:
        raise SelfInstallError(
            f"{path} is not the homenet data folder, so it was not deleted.",
            "homenet only deletes its own data folder, never a parent directory.",
        )
    if not _safe_directory(path, root):
        _refuse_outside(path)
    _remove_tree(path)


def _holds_running_editable(checkout: Path) -> bool:
    """True when this process is an editable install from ``checkout``."""
    try:
        dist = distribution(DIST_NAME)
    except PackageNotFoundError:
        return False
    source = _editable_source(_direct_url(dist))
    if not source:
        return False
    src = _realpath(Path(source))
    root = _realpath(checkout)
    if not src or not root:
        return True
    if src == root:
        return True
    try:
        return os.path.commonpath([src, root]) == root
    except ValueError:
        return True


def remove_checkout(path: Path, *, home: Path, environ: Mapping[str, str] | None = None) -> None:
    """Delete one source checkout after the same checks as the search.

    When the checkout holds the running editable install, raises
    :class:`SelfInstallError` with the manual uninstall steps.
    """
    env = os.environ if environ is None else environ
    root = _home_from_env(env, home)
    if root is None:
        raise SelfInstallError(HOME_UNSET_MESSAGE)
    if path.name != CHECKOUT_DIR_NAME or not _is_checkout(path):
        raise SelfInstallError(
            f"{path} is not a homenet-cli source checkout, so it was not deleted.",
            "homenet only deletes a folder named homenet-cli whose pyproject.toml "
            "names homenet-cli.",
        )
    if not _safe_directory(path, root):
        _refuse_outside(path)
    if _holds_running_editable(path):
        message, hint = _manual(KIND_EDITABLE, DIST_NAME, str(path))
        raise SelfInstallError(message, hint)
    _remove_tree(path)


def purge_saved_data(
    environ: Mapping[str, str] | None = None, home: Path | None = None
) -> tuple[Path, ...]:
    """Remove the homenet data directory when the containment checks pass.

    Does not search for or delete source checkouts. Returns the baseline file
    (when it was a real file) and the directory. Returns an empty tuple when
    ``HOME`` is unset, the directory is missing, or the path is refused.
    Raises :class:`SelfInstallError` when a safe directory cannot be deleted.
    """
    env = os.environ if environ is None else environ
    root = _home_from_env(env, home)
    if root is None:
        return ()
    directory, baseline = _planned_data(env, root)
    if directory is None:
        return ()
    remove_data_dir(directory, home=root, environ=env)
    removed: list[Path] = []
    if baseline is not None:
        removed.append(baseline)
    removed.append(directory)
    return tuple(removed)


def run_uninstall(cmd: Command, timeout: float = UNINSTALL_TIMEOUT) -> None:
    """Run exactly ``cmd.argv`` (no shell) and raise :class:`SelfInstallError` on failure."""
    try:
        proc = run_command(cmd, timeout)
    except subprocess.TimeoutExpired as exc:
        raise SelfInstallError(
            f"Uninstall did not finish within {timeout:g} seconds.",
            "Run the command shown above yourself.",
        ) from exc
    except FileNotFoundError as exc:
        program = cmd.argv[0] if cmd.argv else "the uninstaller"
        raise SelfInstallError(
            f"Could not run {program}.",
            "Install that program, or follow the manual steps for your system.",
        ) from exc
    except PermissionError as exc:
        raise SelfInstallError(
            "Permission denied while uninstalling.",
            "Run the command shown above yourself.",
        ) from exc
    if proc.returncode == 0:
        return
    detail = (proc.stderr or proc.stdout or "").strip().splitlines()
    snippet = clean_text(" ".join(detail[:3])) if detail else None
    message = f"Uninstall failed (exit {proc.returncode})."
    if snippet:
        message = f"{message} {snippet}"
    raise SelfInstallError(message, "Run the command shown above yourself and read its message.")

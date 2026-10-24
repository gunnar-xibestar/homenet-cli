"""Detect how this copy of homenet was installed, and uninstall it.

Uses :class:`~homenet.core.commands.Command` and :func:`~homenet.core.commands.run_command`,
so the command hook sees the real argv. Never prints and never calls ``sys.exit``.
Saved data is the baseline path from :mod:`homenet.core.baseline`.

``--purge`` may delete only two kinds of path, and only when that is safe:

* ``baseline.json`` inside the homenet data directory (``$XDG_DATA_HOME/homenet``
  when that variable is an absolute path, otherwise ``~/.local/share/homenet``).
  The directory itself is removed only when that leaves it empty. Any other
  name is kept and reported.
* a source checkout under the home directory, and only when it is a pristine
  git repository: a real ``.git`` directory, and only allowlisted config
  (``core.bare`` must be false; ``.git/config.worktree`` is held to the same
  list). The list is the keys a normal clone writes, plus branch, remote,
  pull, fetch, and push policy that cannot run a command or point at another
  path, and ``init.defaultbranch``, ``user.name``, and ``user.email``.
  Any other section or key, ``include`` / ``includeIf``, or a value that does
  not parse keeps it. So does ``.git/commondir``,
  ``.git/gitdir``, ``.git/objects/info/alternates``, content in
  ``.git/info/attributes`` beyond whitespace and comments, a ``filter=`` or
  ``diff=`` line in ``.gitattributes``, a mount inside the tree, a stash,
  local or ignored or untracked files, or unpushed commits on an upstream.
  A config refusal names the first offending key and not its value, and names
  ``config.worktree`` when that file has the key.

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
is deleted. Git config and attributes are read before ``git`` runs. A
section or key outside the clone allowlist, a value that does not parse, a
linked git file, or a ``filter=`` / ``diff=`` attribute refuses that
checkout, and ``git`` is not started for it. The distribution name on the
uninstall command is always ``homenet-cli``.
"""

from __future__ import annotations

import json
import os
import re
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
# Names homenet itself writes. Anything else in the data directory is kept.
DATA_FILE_NAMES = frozenset({BASELINE_FILENAME})
_CONFIG_READ_LIMIT = 1024 * 1024
# Clone bookkeeping. These booleans only record how the filesystem and refs
# behave. core keys that name a path, a program, a hook, or attributes are
# not in this set.
_CORE_BOOL_KEYS = frozenset(
    {
        "filemode",
        "logallrefupdates",
        "ignorecase",
        "precomposeunicode",
    }
)
# Where this remote fetches and pushes, and whether a fetch prunes or skips
# it. url, fetch, and pushurl are location strings, not programs. tagopt is
# only the --tags / --no-tags switch. promisor and partialclonefilter are
# absent because those make status fetch.
_REMOTE_STRING_KEYS = frozenset({"url", "fetch", "pushurl"})
_REMOTE_BOOL_KEYS = frozenset({"prune", "skipdefaultupdate"})
_REMOTE_TAGOPT_KEY = "tagopt"
# How a branch merges, rebases, and which remote it pushes to, plus a
# description string. None of these names a program, a path, or a work tree.
_BRANCH_STRING_KEYS = frozenset({"remote", "merge", "pushremote", "description"})
_BRANCH_REBASE_KEY = "rebase"
# pull.rebase and pull.ff only choose merge versus rebase and fast-forward.
_PULL_KEYS = frozenset({"rebase", "ff"})
# fetch.prune only drops stale remote-tracking refs when a fetch runs.
_FETCH_KEYS = frozenset({"prune"})
# What a push with no refspec updates, and whether that push sets upstream.
_PUSH_KEYS = frozenset({"default", "autosetupremote"})
# The branch name ``git init`` would create. It is not a directory.
_INIT_KEYS = frozenset({"defaultbranch"})
# Identity strings stored on a commit. They are not commands or paths.
_USER_KEYS = frozenset({"name", "email"})
# Documented non-boolean values of branch.<name>.rebase and pull.rebase.
_REBASE_WORDS = frozenset({"merges", "m", "interactive", "i", "preserve", "p"})
_TAGOPT_VALUES = frozenset({"--tags", "--no-tags"})
_PUSH_DEFAULT_VALUES = frozenset(
    {"nothing", "current", "upstream", "tracking", "simple", "matching"}
)
_GIT_BOOL_TRUE = frozenset({"true", "yes", "on", "1"})
_GIT_BOOL_FALSE = frozenset({"false", "no", "off", "0"})
_LINKED_GIT_PARTS = (
    ("commondir",),
    ("gitdir",),
    ("objects", "info", "alternates"),
)
_GIT_CONFIG_ARGS = (
    "-c",
    "core.fsmonitor=false",
    "-c",
    "core.hooksPath=/dev/null",
)

KIND_VENV = "venv"
KIND_PIPX = "pipx"
KIND_USER = "user"
KIND_SYSTEM = "system"
KIND_EDITABLE = "editable"
KIND_UNKNOWN = "unknown"
KIND_DEB = "deb"
KIND_BINARY = "binary"

# Written by the Debian package. Its stripped content is exactly ``deb``.
DEB_MARKER = Path("/usr/lib/homenet/install-method")
_DEB_MARKER_LIMIT = 4096
DEB_HINT = "Remove it with `sudo apt remove homenet`."
DEB_MESSAGE = (
    "This copy of homenet was installed as a system package, so homenet did not remove it."
)
HOME_ROOT_MESSAGE = (
    "HOME points at the root folder (/), so homenet did not plan or delete anything."
)
HOME_RELATIVE_MESSAGE = (
    "HOME is not an absolute path (it must start with /), "
    "so homenet did not plan or delete anything."
)
HOME_FIX_HINT = "Set HOME to your own home folder, then run `homenet uninstall --purge` again."

_AUTOMATIC = frozenset({KIND_VENV, KIND_PIPX, KIND_USER})


class SelfInstallError(Exception):
    """A refused or failed uninstall. ``hint`` is the beginner-friendly fix."""

    def __init__(self, message: str, hint: str | None = None) -> None:
        super().__init__(message)
        self.hint = hint


@dataclass(frozen=True)
class InstallInfo:
    """How this process's homenet was installed.

    ``command`` is set only for a venv, pipx, or user-site install. System,
    editable, deb, binary, and unknown installs stay ``None`` so nothing is
    executed. ``binary`` is the resolved executable of a frozen binary in
    ``~/.local/bin``; that one file is the only thing a binary uninstall removes.
    ``binary_identity`` is its ``st_dev, st_ino`` (lstat) captured at detection.
    """

    kind: str
    distribution: str
    command: Command | None
    message: str
    hint: str | None = None
    binary: Path | None = None
    binary_identity: tuple[int, int] | None = None

    @property
    def automatic(self) -> bool:
        return self.command is not None and self.kind in _AUTOMATIC


def _within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except (ValueError, OSError):
        return False
    return True


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
        venvs = root / "venvs"
        # The prefix is the venv root, a direct child of pipx's venvs directory.
        if prefix.parent == venvs and _within(prefix, venvs):
            return True
    # Same layout outside the default home: <dir>/pipx/venvs/<name>, and nothing looser.
    parent = prefix.parent
    return parent.name == "venvs" and parent.parent.name == "pipx"


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
            "It was installed by your system package manager. Remove it with that tool. "
            f"If root pip installed it, run {root_pip}.",
        )
    return (
        "homenet could not tell how this copy was installed, so it was not removed.",
        f"From the environment that installed it, run {pip}. "
        "If a system package manager installed it, remove it with that tool.",
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
    marker: Path | None = None,
    frozen: bool | None = None,
) -> InstallInfo:
    """Classify this install. Runs nothing.

    Signals, in order: the deb marker file (``marker``, default
    :data:`DEB_MARKER`) whose stripped content is ``deb``; a frozen executable
    that resolves inside ``~/.local/bin``; then ``direct_url.json`` editable, the pipx home (env or
    ``~/.local/pipx``), ``sys.prefix`` against ``sys.base_prefix``, then
    :func:`site.getusersitepackages`. Anything else found on the system
    prefix is system/apt. A missing distribution is unknown.
    """
    env = os.environ if environ is None else environ
    prefix = sys.prefix if prefix is None else prefix
    base_prefix = sys.base_prefix if base_prefix is None else base_prefix
    executable = sys.executable if executable is None else executable
    if is_deb_install(DEB_MARKER if marker is None else marker):
        return InstallInfo(KIND_DEB, DIST_NAME, None, DEB_MESSAGE, DEB_HINT)
    frozen = bool(getattr(sys, "frozen", False)) if frozen is None else frozen
    binary = _frozen_binary(executable, env) if frozen else None
    if binary is not None:
        try:
            info = os.lstat(binary)
        except OSError:
            info = None
        if info is not None and stat.S_ISREG(info.st_mode):
            identity = (info.st_dev, info.st_ino)
            return InstallInfo(KIND_BINARY, DIST_NAME, None, "", None, binary, identity)
    try:
        dist = distribution(DIST_NAME)
    except PackageNotFoundError:
        message, hint = _manual(KIND_UNKNOWN, DIST_NAME, None)
        return InstallInfo(KIND_UNKNOWN, DIST_NAME, None, message, hint)

    kind, source = _classify(dist, prefix=prefix, base_prefix=base_prefix, environ=env)
    if kind == KIND_PIPX:
        command = Command(("pipx", "uninstall", DIST_NAME), f"uninstall {DIST_NAME} with pipx")
        return InstallInfo(kind, DIST_NAME, command, "")
    if kind in {KIND_VENV, KIND_USER}:
        return InstallInfo(kind, DIST_NAME, _pip_command(executable, DIST_NAME, kind), "")
    message, hint = _manual(kind, DIST_NAME, source)
    return InstallInfo(kind, DIST_NAME, None, message, hint)


def is_deb_install(marker: Path = DEB_MARKER) -> bool:
    """True when ``marker`` is a regular file whose stripped content is ``deb``."""
    try:
        info = os.stat(marker)
        if not stat.S_ISREG(info.st_mode) or info.st_size > _DEB_MARKER_LIMIT:
            return False
        text = Path(marker).read_text(encoding="utf-8", errors="replace")
    except (OSError, ValueError):
        return False
    return text.strip() == "deb"


def _local_bin(home: Path) -> Path:
    return Path(os.path.abspath(os.fspath(home))) / ".local" / "bin"


def _frozen_binary(executable: str, environ: Mapping[str, str]) -> Path | None:
    """The resolved executable when it is a file inside ``~/.local/bin``, else None."""
    home = _home_from_env(environ, None)
    if home is None or not executable:
        return None
    try:
        resolved = Path(executable).resolve()
    except (OSError, ValueError):
        return None
    if not resolved.is_file() or not _within(resolved, _local_bin(home)):
        return None
    return resolved


def check_binary(path: Path, home: Path) -> None:
    """Raise unless ``path`` is a regular file directly inside ``home/.local/bin``.

    A symbolic link, at the file or any folder from ``home`` down, is refused,
    so a link that points elsewhere is never followed.
    """
    refusal = SelfInstallError(
        f"{path} is not a homenet binary inside ~/.local/bin, so it was not removed.",
        "homenet only removes its own executable file from ~/.local/bin. "
        "Delete it yourself if you still want it gone.",
    )
    root = _home_from_env({}, home)
    if root is None or _home_is_root(root):
        raise refusal
    target = Path(os.path.abspath(os.fspath(path)))
    if target.parent != _local_bin(root) or not _contained(target, root):
        raise refusal
    if _has_symlink_component(target, root):
        raise refusal
    try:
        info = os.lstat(target)
    except OSError as exc:
        raise refusal from exc
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise refusal


def remove_binary(path: Path, *, home: Path, identity: tuple[int, int]) -> Path:
    """Delete one frozen homenet binary after :func:`check_binary`. Returns the path.

    The folder is opened with ``O_NOFOLLOW`` from ``home`` down. The file is
    unlinked only when it is still a regular file whose ``st_dev, st_ino``
    match ``identity`` from detection. Nothing else is touched.
    """
    check_binary(path, home)
    target = Path(os.path.abspath(os.fspath(path)))
    parent, directory, _name = _open_chain(home, target.parent)
    try:
        try:
            info = os.stat(target.name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError as exc:
            raise _binary_changed(target) from exc
        same = (info.st_dev, info.st_ino) == tuple(identity)
        if not same or not stat.S_ISREG(info.st_mode):
            raise _binary_changed(target)
        os.unlink(target.name, dir_fd=directory)
    except OSError as exc:
        raise _delete_error(target, exc) from exc
    finally:
        os.close(directory)
        os.close(parent)
    return target


def _binary_changed(path: Path) -> SelfInstallError:
    return SelfInstallError(
        f"{path} changed after homenet checked it, so it was not removed.",
        "Delete that file yourself if you are sure it is homenet.",
    )


def _home_is_root(home: Path) -> bool:
    try:
        return Path(home).resolve() == Path("/")
    except (OSError, RuntimeError, ValueError):
        return True


def check_purge_home(environ: Mapping[str, str] | None = None) -> None:
    """Refuse ``--purge`` when ``HOME`` is unset, empty, relative, or resolves to ``/``."""
    env = os.environ if environ is None else environ
    raw = env.get("HOME")
    text = "" if raw is None else str(raw).strip()
    if not text:
        raise SelfInstallError(HOME_UNSET_MESSAGE, HOME_FIX_HINT)
    if not os.path.isabs(text):
        raise SelfInstallError(HOME_RELATIVE_MESSAGE, HOME_FIX_HINT)
    root = Path(text)
    if _home_is_root(root):
        raise SelfInstallError(HOME_ROOT_MESSAGE, HOME_FIX_HINT)


def plan_uninstall() -> list[Command]:
    """The uninstall command, or :class:`SelfInstallError` when nothing may run.

    A deb install plans nothing (the fix is apt). A binary install removes one
    file and runs no command, so it plans nothing either.
    """
    info = detect_install()
    if info.kind in {KIND_DEB, KIND_BINARY}:
        return []
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
    """A source checkout under the home directory.

    ``reason`` is set when the checkout must be kept. ``identity`` is the
    ``st_dev, st_ino`` pair captured when it was safe to consider deleting.
    """

    path: Path
    reason: str | None = None
    identity: tuple[int, int] | None = None

    @property
    def deletable(self) -> bool:
        return self.reason is None and self.identity is not None


@dataclass(frozen=True)
class DataRemoval:
    """What a data-directory purge actually did.

    ``left`` is the names still in the directory. The directory itself is
    removed only when ``left`` is empty.
    """

    removed: tuple[Path, ...]
    left: tuple[str, ...]
    directory: Path
    directory_removed: bool


@dataclass(frozen=True)
class PurgePlan:
    """What ``--purge`` may delete. Paths already passed the containment checks.

    ``blocked`` is set when nothing may be deleted, which is when ``HOME`` is
    unset or empty. ``data_dir`` is the homenet data directory when it is safe
    to modify, or None. ``baseline`` is ``baseline.json`` when that file will
    be deleted. ``data_left`` is every other name in the directory. The
    directory is removed only when ``remove_data_directory`` is true.
    ``checkouts`` includes both pristine checkouts and ones that are kept,
    with a reason.
    """

    home: Path | None
    data_dir: Path | None
    baseline: Path | None
    checkouts: tuple[SourceCheckout, ...]
    blocked: str | None = None
    data_left: tuple[str, ...] = ()
    remove_data_directory: bool = False
    data_identity: tuple[int, int] | None = None


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


def _keep(reason: str) -> str:
    """Why a checkout stays on disk. The user deletes it if they still want to."""
    return f"{reason}; delete it yourself"


def _dir_identity(path: Path) -> tuple[int, int] | None:
    try:
        info = os.lstat(path)
    except OSError:
        return None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        return None
    return (info.st_dev, info.st_ino)


class _GitUnavailable(Exception):
    """``git`` is not installed."""


def _git_env(git_dir: str, work_tree: str) -> dict[str, str]:
    """Environment for git, pinned to one checkout.

    Inherited ``GIT_*`` variables are dropped first, including ``GIT_DIR``,
    ``GIT_WORK_TREE``, ``GIT_INDEX_FILE``, ``GIT_OBJECT_DIRECTORY``,
    ``GIT_COMMON_DIR``, and ``GIT_CEILING_DIRECTORIES``. The directory and
    work tree are then set to the checkout being checked.
    """
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env["GIT_DIR"] = git_dir
    env["GIT_WORK_TREE"] = work_tree
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_CONFIG_GLOBAL"] = "/dev/null"
    env["GIT_OPTIONAL_LOCKS"] = "0"
    env["GIT_TERMINAL_PROMPT"] = "0"
    return env


def _git(
    checkout: Path, args: tuple[str, ...], purpose: str
) -> subprocess.CompletedProcess[str] | None:
    """Run git pinned to ``checkout``. None means the command failed. Missing git raises.

    ``--git-dir`` and ``--work-tree`` are the resolved checkout, so ``core.worktree``
    cannot point git at another clone. ``-c`` turns off fsmonitor and hooks.
    Callers refuse a repository config that can run a command before they get here.
    """
    work_tree = _realpath(checkout)
    if not work_tree:
        return None
    git_dir = os.path.join(work_tree, ".git")
    command = Command(
        ("git", f"--git-dir={git_dir}", f"--work-tree={work_tree}", *_GIT_CONFIG_ARGS, *args),
        purpose,
    )
    try:
        return run_command(command, GIT_TIMEOUT, env=_git_env(git_dir, work_tree))
    except FileNotFoundError as exc:
        raise _GitUnavailable from exc
    except (subprocess.TimeoutExpired, PermissionError, OSError):
        return None


def _strip_config_comment(line: str) -> str:
    """Drop ``#`` and ``;`` comments that sit outside quotes."""
    quote = ""
    kept: list[str] = []
    index = 0
    while index < len(line):
        char = line[index]
        if quote:
            kept.append(char)
            if char == "\\" and index + 1 < len(line):
                kept.append(line[index + 1])
                index += 2
                continue
            if char == quote:
                quote = ""
            index += 1
            continue
        if char in "\"'":
            quote = char
            kept.append(char)
            index += 1
            continue
        if char in "#;":
            break
        kept.append(char)
        index += 1
    return "".join(kept)


def _split_section(header: str) -> tuple[str, str]:
    """``(family, subsection)``, both lowercased.

    The family is the first dotted piece, so ``[filter.evil]`` and
    ``[filter "evil"]`` are both the ``filter`` family. ``[Filter.Evil]``
    matches the same way.
    """
    header = header.strip()
    if not header:
        return "", ""
    token, _, rest = header.partition(" ")
    family_token = token.strip("\"'").lower()
    family, dotted, dotted_sub = family_token.partition(".")
    quoted = rest.strip()
    if len(quoted) >= 2 and quoted[0] == quoted[-1] and quoted[0] in "\"'":
        return family, quoted[1:-1].lower()
    if dotted:
        return family, dotted_sub
    return family, ""


def _section_end(line: str) -> int | None:
    """Index of the ``]`` that closes a section header, ignoring one inside quotes."""
    quote = ""
    index = 1
    while index < len(line):
        char = line[index]
        if quote:
            if char == "\\" and index + 1 < len(line):
                index += 2
                continue
            if char == quote:
                quote = ""
            index += 1
            continue
        if char in "\"'":
            quote = char
            index += 1
            continue
        if char == "]":
            return index
        index += 1
    return None


def _unescape_config_value(raw: str) -> str | None:
    """Decoded git-config value, or None when the token does not parse.

    An empty token is an empty string. Double quotes and the escapes git
    accepts (``\\\\``, ``\\"``, ``\\n``, ``\\t``, ``\\b``) are decoded.
    A backslash or quote outside a quoted value does not parse.
    """
    value = raw.strip()
    if not value or value[0] != '"':
        if "\\" in value or '"' in value:
            return None
        return value
    out: list[str] = []
    index = 1
    escapes = {"\\": "\\", '"': '"', "n": "\n", "t": "\t", "b": "\b"}
    while index < len(value):
        char = value[index]
        if char == "\\":
            if index + 1 >= len(value):
                return None
            mapped = escapes.get(value[index + 1])
            if mapped is None:
                return None
            out.append(mapped)
            index += 2
            continue
        if char == '"':
            if value[index + 1 :].strip():
                return None
            return "".join(out)
        out.append(char)
        index += 1
    return None


def _git_bool(token: str) -> bool | None:
    """Git's boolean, or None when ``token`` is not one."""
    value = token.strip().lower()
    if value in _GIT_BOOL_TRUE:
        return True
    if value in _GIT_BOOL_FALSE:
        return False
    return None


def _assignment_parts(line: str) -> tuple[str, str | None] | None:
    """``(key, raw value)``. A missing value means the git boolean shorthand ``true``.

    None means the line does not parse. The key is lowercased.
    """
    if "=" in line:
        left, raw = line.split("=", 1)
    else:
        left, raw = line, None
    key = left.strip().strip("\"'")
    if not key or any(char.isspace() for char in key):
        return None
    return key.lower(), raw


def _core_value_allowed(key: str, raw: str | None) -> bool:
    """True for one allowed ``core`` key whose value parses."""
    if key == "repositoryformatversion":
        if raw is None:
            return False
        return _unescape_config_value(raw) in {"0", "1"}
    if key == "bare":
        if raw is None:
            return False
        value = _unescape_config_value(raw)
        return value is not None and _git_bool(value) is False
    if key not in _CORE_BOOL_KEYS:
        return False
    return _bool_value_allowed(raw)


def _string_value_allowed(raw: str | None) -> bool:
    return raw is not None and _unescape_config_value(raw) is not None


def _bool_value_allowed(raw: str | None) -> bool:
    """True for git's boolean, including the shorthand of a missing value."""
    if raw is None:
        return True
    value = _unescape_config_value(raw)
    return value is not None and _git_bool(value) is not None


def _choice_value_allowed(raw: str | None, choices: frozenset[str]) -> bool:
    """True when the value parses and is one of ``choices``, ignoring case."""
    if raw is None:
        return False
    value = _unescape_config_value(raw)
    return value is not None and value.strip().lower() in choices


def _rebase_value_allowed(raw: str | None) -> bool:
    """A git boolean, or merges / interactive / preserve and their one-letter forms."""
    if raw is None:
        return True
    value = _unescape_config_value(raw)
    if value is None:
        return False
    word = value.strip().lower()
    return _git_bool(word) is not None or word in _REBASE_WORDS


def _ff_value_allowed(raw: str | None) -> bool:
    """A git boolean, or ``only`` (``pull --ff-only``)."""
    if raw is None:
        return True
    value = _unescape_config_value(raw)
    if value is None:
        return False
    word = value.strip().lower()
    return _git_bool(word) is not None or word == "only"


def _remote_value_allowed(key: str, raw: str | None) -> bool:
    if key in _REMOTE_STRING_KEYS:
        return _string_value_allowed(raw)
    if key == _REMOTE_TAGOPT_KEY:
        return _choice_value_allowed(raw, _TAGOPT_VALUES)
    if key in _REMOTE_BOOL_KEYS:
        return _bool_value_allowed(raw)
    return False


def _branch_value_allowed(key: str, raw: str | None) -> bool:
    if key in _BRANCH_STRING_KEYS:
        return _string_value_allowed(raw)
    if key == _BRANCH_REBASE_KEY:
        return _rebase_value_allowed(raw)
    return False


def _pull_value_allowed(key: str, raw: str | None) -> bool:
    if key not in _PULL_KEYS:
        return False
    if key == "rebase":
        return _rebase_value_allowed(raw)
    return key == "ff" and _ff_value_allowed(raw)


def _push_value_allowed(key: str, raw: str | None) -> bool:
    if key not in _PUSH_KEYS:
        return False
    if key == "default":
        return _choice_value_allowed(raw, _PUSH_DEFAULT_VALUES)
    return key == "autosetupremote" and _bool_value_allowed(raw)


def _key_value_allowed(family: str, key: str, raw: str | None) -> bool:
    """True when this one key is on the allowlist and its value parses."""
    if family == "core":
        return _core_value_allowed(key, raw)
    if family == "remote":
        return _remote_value_allowed(key, raw)
    if family == "branch":
        return _branch_value_allowed(key, raw)
    if family == "pull":
        return _pull_value_allowed(key, raw)
    if family == "fetch":
        return key in _FETCH_KEYS and _bool_value_allowed(raw)
    if family == "push":
        return _push_value_allowed(key, raw)
    if family == "init":
        return key in _INIT_KEYS and _string_value_allowed(raw)
    if family == "user":
        return key in _USER_KEYS and _string_value_allowed(raw)
    return False


def _section_allowed(family: str, subsection: str) -> bool:
    """True for a flat allowlisted section, or a named remote or branch.

    Flat sections are ``core``, ``pull``, ``fetch``, ``push``, ``init``, and
    ``user``. They take no subsection, so ``[core.bare]`` is not the allowed
    ``bare = false`` line. ``remote`` and ``branch`` require a name. Being in
    this set does not allow every key: each key is listed on its own.
    ``[filter.evil]`` and ``[remote.origin]`` share a shape, and the family is
    the first dotted piece. ``include`` and ``includeIf`` are not in this set.
    """
    if family in {"core", "pull", "fetch", "push", "init", "user"}:
        return not subsection
    if family in {"remote", "branch"}:
        return bool(subsection)
    return False


def _normalized_key(family: str, subsection: str, key: str) -> str:
    """``section.subsection.key`` in the lowercase form the allowlist uses.

    Empty pieces are left out. The value is never included.
    """
    return ".".join(part for part in (family, subsection, key) if part)


def _assignment_offense(family: str, subsection: str, line: str, *, section_ok: bool) -> str | None:
    """Normalized key when ``line`` refuses the file, else None.

    ``""`` means the line refuses and has no key to name.
    """
    parts = _assignment_parts(line)
    if parts is None:
        return ""
    key, raw = parts
    if section_ok and _key_value_allowed(family, key, raw):
        return None
    return _normalized_key(family, subsection, key)


def _continued_key(raw: str, family: str, subsection: str, *, seen_section: bool) -> str:
    """Key named by a continued line. A continued line is always custom."""
    stripped = _strip_config_comment(raw).strip()
    if stripped.endswith("\\"):
        stripped = stripped[:-1].rstrip()
    if not stripped or stripped.startswith("["):
        return ""
    parts = _assignment_parts(stripped)
    if parts is None:
        return ""
    if not seen_section:
        return parts[0]
    return _normalized_key(family, subsection, parts[0])


def _config_offense(text: str) -> str | None:
    """First offending key, or None when ``text`` is only allowlisted keys.

    The key is ``section.subsection.key`` in lowercase, with no value.
    ``""`` means the file is custom but no key could be named. An empty file
    is allowed. A continued line, a broken header, a key before any section,
    any other section or key, ``include`` / ``includeIf``, or a value that
    does not parse is custom.
    """
    family = ""
    subsection = ""
    seen_section = False
    section_ok = False
    saw_assignment = False

    def unnamed_bad_section() -> str | None:
        if seen_section and not section_ok and not saw_assignment:
            return _normalized_key(family, subsection, "") or ""
        return None

    for raw in text.splitlines():
        body = raw.lstrip()
        if raw.rstrip().endswith("\\") and body[:1] not in {"#", ";", ""}:
            return _continued_key(raw, family, subsection, seen_section=seen_section)
        line = _strip_config_comment(raw).strip()
        if not line:
            continue
        if line.startswith("["):
            pending = unnamed_bad_section()
            if pending is not None:
                return pending
            end = _section_end(line)
            if end is None:
                return ""
            family, subsection = _split_section(line[1:end])
            seen_section = True
            section_ok = _section_allowed(family, subsection)
            saw_assignment = False
            rest = line[end + 1 :].strip()
            if rest:
                saw_assignment = True
                offense = _assignment_offense(family, subsection, rest, section_ok=section_ok)
                if offense is not None:
                    return offense
            continue
        if not seen_section:
            parts = _assignment_parts(line)
            if parts is None:
                return ""
            return parts[0]
        saw_assignment = True
        offense = _assignment_offense(family, subsection, line, section_ok=section_ok)
        if offense is not None:
            return offense
    return unnamed_bad_section()


def _read_nofollow(path: Path) -> tuple[bool, str] | None:
    """``(False, "")`` when missing, ``(True, text)`` when read, None when unsafe.

    Symlinks are not followed. None means the checkout must be kept.
    """
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return (False, "")
    except OSError:
        return None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        return None
    if info.st_size > _CONFIG_READ_LIMIT or not hasattr(os, "O_NOFOLLOW"):
        return None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return None
    try:
        data = os.read(fd, _CONFIG_READ_LIMIT + 1)
    except OSError:
        return None
    finally:
        os.close(fd)
    if len(data) > _CONFIG_READ_LIMIT:
        return None
    return (True, data.decode("utf-8", "replace"))


def _config_refusal(checkout: Path) -> str | None:
    """Detail when git config must keep the checkout, else None.

    None means ``.git/config`` and ``.git/config.worktree`` are missing or
    hold only allowlisted keys, so git may run. Otherwise the detail is the
    first offending key (``section.subsection.key``) and never its value. A
    key in ``config.worktree`` is prefixed with that file name. ``""`` means
    the file is unsafe but no key was named: unreadable, a symlink, or broken
    syntax. ``include`` and ``includeIf`` are still refused.
    """
    for name in ("config", "config.worktree"):
        found = _read_nofollow(checkout / ".git" / name)
        if found is None:
            return "config.worktree" if name == "config.worktree" else ""
        present, text = found
        if not present:
            continue
        offense = _config_offense(text)
        if offense is None:
            continue
        if name == "config.worktree":
            return f"config.worktree: {offense}" if offense else "config.worktree"
        return offense
    return None


def _custom_config_reason(detail: str | None) -> str:
    """Refusal for custom config. ``detail`` is a key name, or empty when unnamed."""
    if detail:
        return _keep(f"has custom git config ({detail})")
    return _keep("has custom git config")


def _attributes_assign_command(text: str) -> bool:
    """True when an attributes file sets ``filter=`` or ``diff=``."""
    for raw in text.splitlines():
        line = raw.strip().lower()
        if not line or line.startswith("#"):
            continue
        if "filter=" in line or "diff=" in line:
            return True
    return False


def _attributes_has_rules(text: str) -> bool:
    """True when a line remains after dropping blanks and ``#`` comments."""
    for raw in text.splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            return True
    return False


def _info_attributes_custom(checkout: Path) -> bool:
    """True when ``.git/info/attributes`` exists and is not only comments.

    A missing file is safe. Whitespace and full-line comments are safe. Any
    other line is custom, whether or not it sets ``filter=`` or ``diff=``.
    A symlink or an unreadable file is not safe.
    """
    found = _read_nofollow(checkout / ".git" / "info" / "attributes")
    if found is None:
        return True
    present, text = found
    return present and _attributes_has_rules(text)


def _attributes_can_run_command(checkout: Path) -> bool:
    """True when any work-tree ``.gitattributes`` sets ``filter=`` or ``diff=``.

    Symlinks are not followed. A nested ``.gitattributes`` counts. ``.git``
    itself is not walked.
    """
    try:
        root_dev = os.lstat(checkout).st_dev
    except OSError:
        return True
    for dirpath, dirnames, filenames in os.walk(checkout, topdown=True, followlinks=False):
        current = Path(dirpath)
        kept: list[str] = []
        for name in dirnames:
            if name == ".git":
                continue
            try:
                info = os.lstat(current / name)
            except OSError:
                return True
            if info.st_dev != root_dev:
                return True
            if not stat.S_ISLNK(info.st_mode):
                kept.append(name)
        dirnames[:] = kept
        if ".gitattributes" not in filenames:
            continue
        found = _read_nofollow(current / ".gitattributes")
        if found is None or (found[0] and _attributes_assign_command(found[1])):
            return True
    return False


def _packed_has_stash(text: str) -> bool:
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("^"):
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "refs/stash":
            return True
    return False


def _stash_on_disk(checkout: Path) -> str | None:
    """A stash recorded in ``refs/stash`` or ``packed-refs``, without running git."""
    ref = _read_nofollow(checkout / ".git" / "refs" / "stash")
    if ref is None:
        return _keep("could not be checked")
    if ref[0]:
        return _keep("has a stash")
    packed = _read_nofollow(checkout / ".git" / "packed-refs")
    if packed is None:
        return _keep("could not be checked")
    if packed[0] and _packed_has_stash(packed[1]):
        return _keep("has a stash")
    return None


def _path_exists_nofollow(root: Path, parts: tuple[str, ...]) -> bool | None:
    """True when ``parts`` under ``root`` exists. None means it could not be checked.

    Intermediate directories are not followed. A symlink along the path counts
    as existing and is not opened.
    """
    current = root
    for part in parts:
        current = current / part
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            return False
        except OSError:
            return None
        if stat.S_ISLNK(info.st_mode):
            return True
    return True


def _linked_git_reason(checkout: Path) -> str | None:
    """Refuse a git dir that points at another repository, before git can read it."""
    git_dir = checkout / ".git"
    for parts in _LINKED_GIT_PARTS:
        found = _path_exists_nofollow(git_dir, parts)
        if found is None:
            return _keep("could not be checked")
        if found:
            return _keep("has a linked git directory")
    return None


def _git_dir_reason(checkout: Path) -> str | None:
    """Refuse a missing, linked, or file ``.git`` before git can follow it."""
    git_dir = checkout / ".git"
    try:
        info = os.lstat(git_dir)
    except FileNotFoundError:
        return _keep("is not a git repository")
    except OSError:
        return _keep("could not be checked")
    if stat.S_ISLNK(info.st_mode):
        return _keep("has a linked git directory")
    if not stat.S_ISDIR(info.st_mode):
        return _keep("has a gitdir pointer")
    return None


def _has_foreign_device(path: Path) -> bool:
    """True when ``path`` or anything under it (not through a symlink) is another device.

    A checkout whose own ``st_dev`` differs from its parent is a mount point.
    """
    try:
        root_info = os.lstat(path)
        parent_info = os.lstat(path.parent)
    except OSError:
        return True
    if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
        return True
    if root_info.st_dev != parent_info.st_dev:
        return True
    root_dev = root_info.st_dev
    for dirpath, dirnames, filenames in os.walk(path, topdown=True, followlinks=False):
        current = Path(dirpath)
        try:
            if os.lstat(current).st_dev != root_dev:
                return True
        except OSError:
            return True
        kept: list[str] = []
        for name in dirnames:
            try:
                info = os.lstat(current / name)
            except OSError:
                return True
            if info.st_dev != root_dev:
                return True
            if not stat.S_ISLNK(info.st_mode):
                kept.append(name)
        dirnames[:] = kept
        for name in filenames:
            try:
                info = os.lstat(current / name)
            except OSError:
                return True
            if info.st_dev != root_dev:
                return True
    return False


def _status_reason(text: str) -> str | None:
    """Refuse any porcelain line, including ignored and untracked files."""
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        return None
    for line in lines:
        if line[:2] not in {"??", "!!"}:
            return _keep("has uncommitted changes")
    return _keep("has untracked files")


def _checkout_reason(path: Path) -> str | None:
    """Why ``path`` must be kept. None means it is a pristine git checkout.

    Git is not started when ``.git`` is not a real directory, when
    ``commondir``, ``gitdir``, or ``objects/info/alternates`` exists, when
    config is outside the allowlist, when ``info/attributes`` has
    rules, when a ``.gitattributes`` sets ``filter=`` or ``diff=``, or when
    a stash ref is already on disk. A config refusal names the first key.
    """
    reason = _git_dir_reason(path)
    if reason:
        return reason
    if _has_foreign_device(path):
        return _keep("has a mount inside it")
    reason = _linked_git_reason(path)
    if reason:
        return reason
    refusal = _config_refusal(path)
    if refusal is not None:
        return _custom_config_reason(refusal)
    if _info_attributes_custom(path) or _attributes_can_run_command(path):
        return _keep("has custom git config")
    reason = _stash_on_disk(path)
    if reason:
        return reason
    try:
        status = _git(
            path,
            ("status", "--porcelain", "--ignored", "--untracked-files=all"),
            "check whether the source checkout is clean",
        )
    except _GitUnavailable:
        return _keep("git is not available")
    if status is None or status.returncode != 0:
        return _keep("could not be checked")
    dirty = _status_reason(status.stdout)
    if dirty:
        return dirty
    try:
        ahead = _git(
            path,
            ("rev-list", "--count", "@{upstream}..HEAD"),
            "check whether the source checkout has unpushed commits",
        )
    except _GitUnavailable:
        return _keep("git is not available")
    if ahead is None:
        return _keep("could not be checked")
    if ahead.returncode != 0:
        return _keep("has no upstream")
    count = ahead.stdout.strip()
    if not count.isdigit():
        return _keep("could not be checked")
    if int(count) > 0:
        return _keep("has unpushed commits")
    try:
        listed = _git(path, ("stash", "list"), "check whether the source checkout has a stash")
    except _GitUnavailable:
        return _keep("git is not available")
    if listed is None or listed.returncode != 0:
        return _keep("could not be checked")
    if listed.stdout.strip():
        return _keep("has a stash")
    return None


def _inspect_checkout(path: Path) -> SourceCheckout:
    reason = _checkout_reason(path)
    identity = None if reason else _dir_identity(path)
    if reason is None and identity is None:
        reason = _keep("could not be checked")
    return SourceCheckout(path, reason, identity)


def _will_delete_file(path: Path, root_dev: int) -> bool:
    """True for a regular file on ``root_dev``. Symlinks are kept."""
    try:
        info = os.lstat(path)
    except OSError:
        return False
    return stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode) and info.st_dev == root_dev


def _planned_data(
    environ: Mapping[str, str], home: Path
) -> tuple[Path | None, Path | None, tuple[str, ...], tuple[int, int] | None, bool]:
    """Directory, baseline to delete, names kept, identity, and whether to rmdir.

    The directory is None when it must not be touched at all.
    """
    empty = (None, None, (), None, False)
    directory = data_dir(environ, home)
    root_dir = Path(os.path.abspath(os.sep))
    if directory.name != "homenet":
        return empty
    if _same_path(directory, home) or _same_path(directory, root_dir):
        return empty
    if _same_path(directory, directory.parent) or not _safe_directory(directory, home):
        return empty
    identity = _dir_identity(directory)
    if identity is None:
        return empty
    try:
        names = sorted(os.listdir(directory))
    except OSError:
        return empty
    left: list[str] = []
    baseline: Path | None = None
    for name in names:
        candidate = directory / name
        if name in DATA_FILE_NAMES and _will_delete_file(candidate, identity[0]):
            baseline = candidate
            continue
        left.append(name)
    return directory, baseline, tuple(left), identity, not left


def plan_purge(environ: Mapping[str, str] | None = None, home: Path | None = None) -> PurgePlan:
    """List data files and source checkouts ``--purge`` may delete.

    Git runs only for a checkout whose config cannot run a command. A checkout
    that is not pristine is listed with a reason and is not deleted.
    """
    env = os.environ if environ is None else environ
    root = _home_from_env(env, home)
    if root is None:
        return PurgePlan(None, None, None, (), HOME_UNSET_MESSAGE)
    directory, baseline, left, identity, remove_directory = _planned_data(env, root)
    checkouts = tuple(_inspect_checkout(path) for path in find_source_checkouts(root))
    return PurgePlan(
        root,
        directory,
        baseline,
        checkouts,
        None,
        data_left=left,
        remove_data_directory=remove_directory,
        data_identity=identity,
    )


def _refuse_outside(path: Path) -> None:
    raise SelfInstallError(
        f"{path} is outside the home directory or is a symbolic link, so it was not deleted.",
        "homenet only deletes real folders inside your home directory.",
    )


def _delete_error(path: Path, exc: OSError) -> SelfInstallError:
    return SelfInstallError(
        f"Could not delete {path}: {exc.strerror or exc}",
        "Delete that folder yourself if you still want it gone.",
    )


def _changed(path: Path) -> SelfInstallError:
    return SelfInstallError(
        f"{path} changed while homenet was checking it, so it was not deleted.",
        "homenet left that folder in place.",
    )


def _mount_error(path: Path) -> SelfInstallError:
    return SelfInstallError(
        f"{path} has a mount inside it, so it was not deleted.",
        "homenet left that folder in place.",
    )


def _dir_flags(nofollow: bool) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY
    if nofollow:
        flags |= os.O_NOFOLLOW
    return flags


def _open_chain(home: Path, target: Path) -> tuple[int, int, str]:
    """Open ``target`` from ``home`` without following links below ``home``.

    Returns ``(parent_fd, dir_fd, name)``. The caller closes both descriptors.
    ``home`` itself may be a symlink; components under it may not.
    """
    if not hasattr(os, "O_NOFOLLOW"):
        raise SelfInstallError(
            f"{target} could not be checked, so it was not deleted.",
            "homenet left that folder in place.",
        )
    root = Path(os.path.abspath(os.fspath(home)))
    dest = Path(os.path.abspath(os.fspath(target)))
    try:
        parts = dest.relative_to(root).parts
    except ValueError as exc:
        raise SelfInstallError(
            f"{target} is outside the home directory or is a symbolic link, so it was not deleted.",
            "homenet only deletes real folders inside your home directory.",
        ) from exc
    if not parts:
        _refuse_outside(target)
    fds: list[int] = []
    try:
        fds.append(os.open(root, _dir_flags(False)))
        for part in parts:
            fds.append(os.open(part, _dir_flags(True), dir_fd=fds[-1]))
    except OSError as exc:
        for opened in fds:
            os.close(opened)
        raise SelfInstallError(
            f"{target} is outside the home directory or is a symbolic link, so it was not deleted.",
            "homenet only deletes real folders inside your home directory.",
        ) from exc
    parent = fds[-2]
    directory = fds[-1]
    for opened in fds[:-2]:
        os.close(opened)
    return parent, directory, parts[-1]


def _fd_has_foreign_device(dir_fd: int, root_dev: int) -> bool:
    """True when this directory, opened by fd, contains another device."""
    try:
        if os.fstat(dir_fd).st_dev != root_dev:
            return True
        names = os.listdir(dir_fd)
    except OSError:
        return True
    for name in names:
        try:
            info = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        except OSError:
            return True
        if info.st_dev != root_dev:
            return True
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            continue
        try:
            child = os.open(name, _dir_flags(True), dir_fd=dir_fd)
        except OSError:
            return True
        try:
            opened = os.fstat(child)
            if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                return True
            if _fd_has_foreign_device(child, root_dev):
                return True
        finally:
            os.close(child)
    return False


def _remove_children(dir_fd: int, root_dev: int) -> None:
    """Unlink entries of ``dir_fd``. Directories are opened with ``O_NOFOLLOW``."""
    for name in os.listdir(dir_fd):
        info = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        if info.st_dev != root_dev:
            raise SelfInstallError(
                "A folder changed while homenet was deleting it, so homenet stopped.",
                "Delete the rest of that folder yourself if you still want it gone.",
            )
        if stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode):
            child = os.open(name, _dir_flags(True), dir_fd=dir_fd)
            try:
                opened = os.fstat(child)
                if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                    raise SelfInstallError(
                        "A folder changed while homenet was deleting it, so homenet stopped.",
                        "Delete the rest of that folder yourself if you still want it gone.",
                    )
                _remove_children(child, root_dev)
            finally:
                os.close(child)
            os.rmdir(name, dir_fd=dir_fd)
            continue
        os.unlink(name, dir_fd=dir_fd)


def _unlink_regular(dir_fd: int, name: str, root_dev: int) -> bool:
    """Unlink one allowlisted regular file. Symlinks and other devices stay."""
    try:
        info = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_dev != root_dev:
        return False
    os.unlink(name, dir_fd=dir_fd)
    return True


def remove_data_dir(
    path: Path,
    *,
    home: Path,
    identity: tuple[int, int],
    environ: Mapping[str, str] | None = None,
) -> DataRemoval:
    """Delete allowlisted files in the homenet data directory, through a pinned fd.

    ``path`` must be that directory itself (``.../homenet``), never a parent.
    ``identity`` is the ``st_dev, st_ino`` pair captured when the directory was
    checked. The directory is removed only when it is empty afterwards.
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
    parent, directory, name = _open_chain(root, path)
    try:
        info = os.fstat(directory)
        if (info.st_dev, info.st_ino) != tuple(identity):
            raise _changed(path)
        removed: list[Path] = []
        for filename in sorted(DATA_FILE_NAMES):
            if _unlink_regular(directory, filename, info.st_dev):
                removed.append(path / filename)
        left = tuple(sorted(os.listdir(directory)))
        directory_removed = False
        if not left:
            try:
                os.rmdir(name, dir_fd=parent)
            except OSError:
                left = tuple(sorted(os.listdir(directory)))
            else:
                directory_removed = True
                removed.append(path)
        return DataRemoval(tuple(removed), left, path, directory_removed)
    except OSError as exc:
        raise _delete_error(path, exc) from exc
    finally:
        os.close(directory)
        os.close(parent)


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


def remove_checkout(
    path: Path,
    *,
    home: Path,
    identity: tuple[int, int],
    environ: Mapping[str, str] | None = None,
) -> None:
    """Delete one pristine source checkout through the fd captured for ``path``.

    When the checkout holds the running editable install, raises
    :class:`SelfInstallError` with the manual uninstall steps. A checkout that
    is no longer pristine, or that contains another device, is left in place.
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
    reason = _checkout_reason(path)
    if reason:
        raise SelfInstallError(f"{path} {reason}", "homenet left that folder in place.")
    parent, directory, name = _open_chain(root, path)
    try:
        info = os.fstat(directory)
        if (info.st_dev, info.st_ino) != tuple(identity):
            raise _changed(path)
        if os.fstat(parent).st_dev != info.st_dev or _fd_has_foreign_device(directory, info.st_dev):
            raise _mount_error(path)
        _remove_children(directory, info.st_dev)
        os.rmdir(name, dir_fd=parent)
    except OSError as exc:
        raise _delete_error(path, exc) from exc
    finally:
        os.close(directory)
        os.close(parent)


def purge_saved_data(
    environ: Mapping[str, str] | None = None, home: Path | None = None
) -> tuple[Path, ...]:
    """Remove ``baseline.json`` when the containment checks pass.

    Does not search for or delete source checkouts. Removes the data directory
    only when that leaves it empty. Returns the paths that were actually
    removed. Returns an empty tuple when ``HOME`` is unset, the directory is
    missing, or the path is refused.
    """
    env = os.environ if environ is None else environ
    root = _home_from_env(env, home)
    if root is None:
        return ()
    directory, _baseline, _left, identity, _remove_directory = _planned_data(env, root)
    if directory is None or identity is None:
        return ()
    return remove_data_dir(directory, home=root, identity=identity, environ=env).removed


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

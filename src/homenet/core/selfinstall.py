"""Detect how this copy of homenet was installed, and uninstall it.

Uses :class:`~homenet.core.commands.Command` and :func:`~homenet.core.commands.run_command`,
so the command hook sees the real argv. Never prints and never calls ``sys.exit``.
Saved data is the baseline path from :mod:`homenet.core.baseline`.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import site
import subprocess  # noqa: S404 - TimeoutExpired only; the process is run_command
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError
from importlib.metadata import distribution as distribution
from pathlib import Path
from urllib.parse import unquote, urlparse

from homenet.core._text import clean_text
from homenet.core.baseline import data_dir, default_baseline_path
from homenet.core.commands import Command, run_command

DIST_NAME = "homenet-cli"
APT_PACKAGE = "python3-homenet-cli"
UNINSTALL_TIMEOUT = 120.0

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


def _safe_data_dir(root: Path, baseline: Path) -> bool:
    """True when ``root`` is the homenet data directory and not a symlink."""
    if root.is_symlink() or not root.is_dir():
        return False
    if root.name != "homenet" or baseline.parent != root:
        return False
    try:
        resolved = root.resolve()
    except OSError:
        return False
    if resolved == Path(resolved.anchor):
        return False
    try:
        if resolved == Path.home().resolve():
            return False
    except OSError:
        return False
    return True


def purge_saved_data(
    environ: Mapping[str, str] | None = None, home: Path | None = None
) -> tuple[Path, ...]:
    """Remove the baseline file and the homenet data directory.

    Returns the paths that were actually removed. A symlink at the data
    directory is unlinked and its target is left alone. Raises
    :class:`SelfInstallError` when a path cannot be deleted.
    """
    baseline, root = saved_data_paths(environ, home)
    removed: list[Path] = []
    try:
        if root.is_symlink():
            root.unlink()
            return (root,)
        had_file = baseline.is_file() or (baseline.is_symlink() and not root.is_dir())
        if _safe_data_dir(root, baseline):
            had_baseline = baseline.exists() or baseline.is_symlink()
            shutil.rmtree(root)
            if had_baseline:
                removed.append(baseline)
            removed.append(root)
            return tuple(removed)
        if had_file and baseline.parent == root:
            baseline.unlink()
            removed.append(baseline)
    except OSError as exc:
        raise SelfInstallError(
            f"Could not delete saved data at {root}: {exc.strerror or exc}",
            "Delete that folder yourself if you still want it gone.",
        ) from exc
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

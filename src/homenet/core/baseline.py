"""Save a device baseline and diff it against a new scan. Never prints or exits.

Stored as versioned JSON at ``$XDG_DATA_HOME/homenet/baseline.json``
(default ``~/.local/share/homenet``), written atomically.
"""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from homenet.core.devices import normalize_mac
from homenet.core.parser import Device, Port

SCHEMA_VERSION = 1
BASELINE_FILENAME = "baseline.json"


class BaselineError(Exception):
    def __init__(self, message: str, hint: str | None = None) -> None:
        super().__init__(message)
        self.hint = hint


class BaselineNotFoundError(BaselineError):
    pass


@dataclass
class DeviceDiff:
    new: list[Device] = field(default_factory=list)
    missing: list[Device] = field(default_factory=list)
    changed: list[tuple[Device, Device]] = field(default_factory=list)  # (old, current)
    # Same IP, different MAC: a different device (or MAC randomisation) now uses that IP.
    mac_changed: list[tuple[Device, Device]] = field(default_factory=list)  # (old, current)

    @property
    def has_changes(self) -> bool:
        return bool(self.new or self.missing or self.changed or self.mac_changed)


def data_dir(environ: Mapping[str, str] | None = None, home: Path | None = None) -> Path:
    """``$XDG_DATA_HOME/homenet`` if set to an absolute path, else ``~/.local/share/homenet``."""
    env = os.environ if environ is None else environ
    xdg = env.get("XDG_DATA_HOME", "")
    if xdg and os.path.isabs(xdg):
        return Path(xdg) / "homenet"
    return (home or Path.home()) / ".local" / "share" / "homenet"


def default_baseline_path(
    environ: Mapping[str, str] | None = None, home: Path | None = None
) -> Path:
    return data_dir(environ, home) / BASELINE_FILENAME


def _device_from_dict(d: Mapping) -> Device:
    ports = [
        Port(
            int(p["number"]),
            str(p["protocol"]),
            str(p["state"]),
            p.get("service"),
            p.get("product"),
            p.get("version"),
        )
        for p in d.get("ports") or []
    ]
    return Device(
        ip=str(d["ip"]),
        mac=d.get("mac"),
        vendor=d.get("vendor"),
        hostname=d.get("hostname"),
        ports=ports,
    )


def save_baseline(
    devices: Sequence[Device], path: Path | None = None, *, now: datetime | None = None
) -> Path:
    """Write ``devices`` atomically (temp file + ``os.replace``). Returns the path."""
    path = Path(path) if path else default_baseline_path()
    payload = {
        "schema_version": SCHEMA_VERSION,
        "saved_at": (now or datetime.now(timezone.utc)).isoformat(),
        "devices": [asdict(d) for d in devices],
    }
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".baseline-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, sort_keys=True)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
    except OSError as exc:
        raise BaselineError(
            f"Could not save the baseline to {path}: {exc.strerror or exc}",
            "Check that the folder is writable.",
        ) from exc
    return path


def load_baseline(path: Path | None = None) -> list[Device]:
    """Load a saved baseline. Raises BaselineNotFoundError / BaselineError."""
    path = Path(path) if path else default_baseline_path()
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise BaselineNotFoundError(
            "No baseline saved yet.", "Run `homenet baseline` first."
        ) from exc
    except OSError as exc:
        raise BaselineError(f"Could not read {path}: {exc.strerror or exc}") from exc
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise BaselineError(
            "The saved baseline is corrupted.", "Save a new one with `homenet baseline`."
        ) from exc
    if not isinstance(data, dict) or not isinstance(data.get("devices"), list):
        raise BaselineError(
            "The saved baseline has an unexpected format.",
            "Save a new one with `homenet baseline`.",
        )
    version = data.get("schema_version")
    if version != SCHEMA_VERSION:
        raise BaselineError(
            f"Baseline schema version {version!r} is not supported (expected {SCHEMA_VERSION}).",
            "Save a new one with `homenet baseline`.",
        )
    try:
        return [_device_from_dict(d) for d in data["devices"]]
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise BaselineError(
            "The saved baseline contains an invalid device entry.",
            "Save a new one with `homenet baseline`.",
        ) from exc


def _same(a: Device, b: Device) -> bool:
    return (a.ip, normalize_mac(a.mac), a.vendor, a.hostname, sorted(a.ports, key=repr)) == (
        b.ip,
        normalize_mac(b.mac),
        b.vendor,
        b.hostname,
        sorted(b.ports, key=repr),
    )


def diff_devices(baseline: Sequence[Device], current: Sequence[Device]) -> DeviceDiff:
    """Compare devices keyed by MAC, falling back to IP when a MAC is unknown."""
    result = DeviceDiff()
    unmatched_old = list(baseline)
    pairs: list[tuple[Device, Device]] = []
    rest: list[Device] = []
    for cur in current:
        mac = normalize_mac(cur.mac)
        old = next((o for o in unmatched_old if mac and normalize_mac(o.mac) == mac), None)
        if old is None:
            rest.append(cur)
        else:
            unmatched_old.remove(old)
            pairs.append((old, cur))
    for cur in rest:
        mac = normalize_mac(cur.mac)
        old = next((o for o in unmatched_old if o.ip == cur.ip and (not mac or not o.mac)), None)
        if old is None:
            result.new.append(cur)
        else:
            unmatched_old.remove(old)
            pairs.append((old, cur))
    for cur in list(result.new):
        old = next((o for o in unmatched_old if o.ip == cur.ip), None)
        if old is not None:
            unmatched_old.remove(old)
            result.new.remove(cur)
            result.mac_changed.append((old, cur))
    result.missing = unmatched_old
    result.changed = [(o, c) for o, c in pairs if not _same(o, c)]
    return result

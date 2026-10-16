"""Read-only Wi-Fi link info for the connected interface.

Uses ``nmcli -t`` device/connection fields first (never ``nmcli dev wifi list``,
rescans or connects), then ``iw dev <iface> link`` for radio details. Every
command is built once by a ``build_*_command`` function and executed exactly.
Unavailable states are returned, never raised. Never prints or exits.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess  # noqa: S404 - only via commands.run_command (argv, no shell)
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from homenet.core._text import clean_text
from homenet.core.commands import Command, emit, notify, run_command
from homenet.core.wsl import is_wsl

DEFAULT_TIMEOUT = 5.0
Runner = Callable[[Sequence[str]], str]
_IFACE = re.compile(r"[A-Za-z0-9_.:-]{1,15}")


@dataclass(frozen=True)
class WifiInfo:
    available: bool
    reason: str | None = None  # why not available
    wsl: bool = False
    interface: str | None = None
    ssid: str | None = None
    signal_dbm: int | None = None
    signal_percent: int | None = None
    channel: int | None = None
    frequency_mhz: int | None = None
    band: str | None = None  # "2.4 GHz" | "5 GHz" | "6 GHz"
    link_speed_mbps: float | None = None


# ---- pure helpers ----


def percent_to_dbm(percent: int) -> int:
    """Approximate NetworkManager's quality % as dBm (100% ≈ -50, 0% ≈ -100)."""
    return round(max(0, min(100, percent)) / 2 - 100)


def dbm_to_percent(dbm: int) -> int:
    return max(0, min(100, 2 * (dbm + 100)))


def channel_from_frequency(mhz: int | None) -> int | None:
    if mhz is None:
        return None
    if mhz == 2484:
        return 14
    if 2412 <= mhz <= 2472:
        return (mhz - 2407) // 5
    if 5150 <= mhz <= 5895:
        return (mhz - 5000) // 5
    if 5955 <= mhz <= 7115:
        return (mhz - 5950) // 5
    return None


def band_from_frequency(mhz: int | None) -> str | None:
    if mhz is None:
        return None
    if 2400 <= mhz < 2500:
        return "2.4 GHz"
    if 5150 <= mhz <= 5895:
        return "5 GHz"
    if 5925 <= mhz <= 7125:
        return "6 GHz"
    return None


def parse_nmcli_fields(text: str) -> dict[str, str]:
    """``nmcli -t`` ``KEY:value`` lines -> dict (``\\:`` and ``\\\\`` unescaped left to right)."""
    out = {}
    for line in (text or "").splitlines():
        key, sep, value = line.partition(":")
        if sep:
            out[key.strip()] = re.sub(r"\\([\\:])", r"\1", value).strip()
    return out


def parse_iw_link(text: str) -> dict:
    """Parse ``iw dev <iface> link``. Returns {} when not connected."""
    text = text or ""
    if not text.strip() or text.strip().lower().startswith("not connected"):
        return {}
    info: dict = {}
    if m := re.search(r"^\s*SSID:\s*(.*)$", text, re.MULTILINE):
        info["ssid"] = m.group(1)
    if m := re.search(r"^\s*freq:\s*([\d.]+)", text, re.MULTILINE):
        info["frequency_mhz"] = int(float(m.group(1)))
    if m := re.search(r"^\s*signal:\s*(-?\d+)\s*dBm", text, re.MULTILINE):
        info["signal_dbm"] = int(m.group(1))
    if m := re.search(r"^\s*tx bitrate:\s*([\d.]+)\s*MBit/s", text, re.MULTILINE):
        info["link_speed_mbps"] = float(m.group(1))
    return info


def find_wifi_interface(
    listdir: Callable[[str], list[str]] | None = None,
    exists: Callable[[str], bool] | None = None,
) -> str | None:
    """First interface with a ``/sys/class/net/<iface>/wireless`` directory."""
    try:
        names = sorted((listdir or os.listdir)("/sys/class/net"))
    except OSError:
        return None
    check = exists or os.path.isdir
    for name in names:
        if _IFACE.fullmatch(name) and check(f"/sys/class/net/{name}/wireless"):
            return name
    return None


# ---- command builders (single source of display + execution) ----


def _iface(iface: str) -> str:
    if not _IFACE.fullmatch(iface or "") or iface.startswith("-"):
        raise ValueError(f"{iface!r} is not a valid interface name")
    return iface


def build_nmcli_device_command(iface: str, path: str | None = None) -> Command:
    return Command(
        (
            path or "nmcli",
            "-t",
            "-f",
            "GENERAL.STATE,GENERAL.CONNECTION",
            "device",
            "show",
            _iface(iface),
        ),
        f"read the Wi-Fi connection state of {iface}",
    )


def build_nmcli_ssid_command(connection: str, path: str | None = None) -> Command:
    if not connection or connection.startswith("-"):
        raise ValueError("bad connection name")
    return Command(
        (
            path or "nmcli",
            "-t",
            "-f",
            "802-11-wireless.ssid",
            "connection",
            "show",
            "id",
            connection,
        ),
        "read the network name (SSID) of the active connection",
    )


def build_iw_link_command(iface: str, path: str | None = None) -> Command:
    return Command(
        (path or "iw", "dev", _iface(iface), "link"),
        f"read Wi-Fi signal, frequency and speed of {iface}",
    )


def _exec(cmd: Command, run: Runner | None, timeout: float) -> str:
    if run is not None:
        notify(cmd)
        return run(list(cmd.argv))
    proc = run_command(cmd, timeout)
    if proc.returncode != 0:
        raise subprocess.CalledProcessError(proc.returncode, list(cmd.argv), proc.stdout)
    return proc.stdout or ""


def plan_wifi_commands(
    iface: str | None = None,
    *,
    connection: str | None = None,
    which: Callable[[str], str | None] | None = None,
    listdir=None,
    exists=None,
) -> list[Command]:
    """Commands get_wifi_info would run (reads /sys only; runs nothing).

    The SSID lookup needs the connection name nmcli reports, so it is only
    listed when ``connection`` is given.
    """
    which = which or shutil.which
    iface = iface or find_wifi_interface(listdir, exists)
    if iface is None:
        return []
    cmds = []
    if nmcli := which("nmcli"):
        cmds.append(build_nmcli_device_command(iface, nmcli))
        if connection:
            cmds.append(build_nmcli_ssid_command(connection, nmcli))
    if iw := which("iw"):
        cmds.append(build_iw_link_command(iface, iw))
    return cmds


# ---- main entry point ----


def get_wifi_info(
    iface: str | None = None,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    on_step: Callable[[str], None] | None = None,
    which: Callable[[str], str | None] | None = None,
    run: Runner | None = None,
    listdir=None,
    exists=None,
    wsl_check: Callable[[], bool] | None = None,
) -> WifiInfo:
    """Describe the current Wi-Fi link. Never raises for unavailable states."""
    which = which or shutil.which
    wsl = (wsl_check or is_wsl)()
    if wsl:
        return WifiInfo(False, "WSL", wsl=True)
    emit(on_step, "Looking for a Wi-Fi interface")
    if iface is not None:
        try:
            iface = _iface(iface)
        except ValueError:
            return WifiInfo(False, "no Wi-Fi interface")
    iface = iface or find_wifi_interface(listdir, exists)
    if iface is None:
        return WifiInfo(False, "no Wi-Fi interface")
    nmcli, iw = which("nmcli"), which("iw")
    if not nmcli and not iw:
        return WifiInfo(False, "nmcli/iw not installed", interface=iface)

    ssid = None
    connected = None
    if nmcli:
        emit(on_step, f"Reading Wi-Fi state of {iface} (nmcli)")
        try:
            fields = parse_nmcli_fields(
                _exec(build_nmcli_device_command(iface, nmcli), run, timeout)
            )
            state = fields.get("GENERAL.STATE", "")
            connected = state.startswith("100") or "(connected)" in state
            conn = fields.get("GENERAL.CONNECTION") or None
            if connected and conn and conn != "--":
                out = _exec(build_nmcli_ssid_command(conn, nmcli), run, timeout)
                ssid = parse_nmcli_fields(out).get("802-11-wireless.ssid") or None
        except (OSError, ValueError, subprocess.SubprocessError):
            connected = None
    link: dict = {}
    if iw and connected is not False:
        emit(on_step, f"Reading Wi-Fi link of {iface} (iw)")
        try:
            link = parse_iw_link(_exec(build_iw_link_command(iface, iw), run, timeout))
        except (OSError, ValueError, subprocess.SubprocessError):
            link = {}
        if connected is None:
            connected = bool(link)
    if not connected:
        return WifiInfo(False, "not connected", interface=iface)

    freq = link.get("frequency_mhz")
    dbm = link.get("signal_dbm")
    return WifiInfo(
        True,
        interface=iface,
        ssid=clean_text(ssid or link.get("ssid"), 64),
        signal_dbm=dbm,
        signal_percent=dbm_to_percent(dbm) if dbm is not None else None,
        channel=channel_from_frequency(freq),
        frequency_mhz=freq,
        band=band_from_frequency(freq),
        link_speed_mbps=link.get("link_speed_mbps"),
    )

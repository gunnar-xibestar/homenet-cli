"""Read this computer's listening sockets with ``ss``."""

from __future__ import annotations

import re
import shutil
import subprocess  # noqa: S404 - fixed argv only
from collections.abc import Callable
from dataclasses import dataclass

from homenet.core._text import clean_text
from homenet.core.commands import Command, run_command

LOCAL_PORT_TIMEOUT = 5


class LocalPortsError(Exception):
    """The local listening sockets could not be read."""

    def __init__(self, message: str, hint: str | None = None) -> None:
        super().__init__(message)
        self.hint = hint


@dataclass(frozen=True)
class Listener:
    protocol: str
    address: str
    port: int
    process: str | None = None
    pid: int | None = None


def build_local_ports_commands(ss_path: str | None = None) -> list[Command]:
    """Build the TCP and UDP listening socket commands, without running them."""
    path = ss_path or shutil.which("ss")
    if path is None:
        raise LocalPortsError(
            "The `ss` command is not installed.",
            "Install iproute2, for example: sudo apt install iproute2.",
        )
    return [
        Command((path, "-ltnp"), "list this computer's TCP listening sockets"),
        Command((path, "-lunp"), "list this computer's UDP listening sockets"),
    ]


_PROCESS = re.compile(r'\("([^"\n]+)",pid=(\d+)')


def _parse_ss(text: str, protocol: str) -> list[Listener]:
    listeners: list[Listener] = []
    for line in text.splitlines()[1:]:  # skip ss's column header
        columns = line.split(None, 5)
        if len(columns) < 4:
            continue
        endpoint = columns[3]
        address, separator, raw_port = endpoint.rpartition(":")
        if not separator or not raw_port.isdigit():
            continue
        process_match = _PROCESS.search(columns[5]) if len(columns) > 5 else None
        process = clean_text(process_match.group(1), max_len=128) if process_match else None
        pid = int(process_match.group(2)) if process_match else None
        listeners.append(
            Listener(
                protocol=protocol,
                address=clean_text(address.strip("[]"), max_len=128),
                port=int(raw_port),
                process=process,
                pid=pid,
            )
        )
    return listeners


def scan_local_ports(
    *,
    run: Callable[[Command], subprocess.CompletedProcess[str]] | None = None,
    ss_path: str | None = None,
) -> list[Listener]:
    """Read local TCP and UDP listeners. Process details depend on permissions."""
    execute = run or (lambda cmd: run_command(cmd, LOCAL_PORT_TIMEOUT))
    listeners: list[Listener] = []
    try:
        for command, protocol in zip(build_local_ports_commands(ss_path), ("tcp", "udp"), strict=True):
            result = execute(command)
            if result.returncode:
                detail = (result.stderr or "").strip()
                raise LocalPortsError(
                    f"Could not read local {protocol.upper()} listeners"
                    + (f": {clean_text(detail, max_len=300)}" if detail else "."),
                    "Check that `ss` from iproute2 is available and try again.",
                )
            listeners.extend(_parse_ss(result.stdout or "", protocol))
    except LocalPortsError:
        raise
    except (OSError, subprocess.SubprocessError) as exc:
        raise LocalPortsError(
            f"Could not read local listening ports: {clean_text(str(exc), max_len=300)}",
            "Check that `ss` from iproute2 is available and try again.",
        ) from exc
    return sorted(listeners, key=lambda item: (item.port, item.protocol, item.address))


def plan_local_ports(*, ss_path: str | None = None) -> list[Command]:
    """Commands used by ``homenet ports --local``; nothing is executed."""
    return build_local_ports_commands(ss_path)

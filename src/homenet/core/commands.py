"""The real commands homenet runs, as data.

Every wrapper builds a :class:`Command` with one ``build_*_command`` function and
executes exactly ``cmd.argv`` (or fetches exactly ``cmd.url``), so what is shown
and what runs cannot drift. Planners apply the same validation but run nothing.
Socket reverse DNS is a library call, not a command, and is not listed.
Never prints or exits.
"""

from __future__ import annotations

import shlex
import subprocess  # noqa: S404 - argument lists only, shell=False
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

from homenet.core._text import clean_text

CommandHook = Callable[["Command"], None]
_hook: CommandHook | None = None


@dataclass(frozen=True)
class Command:
    argv: tuple[str, ...]
    purpose: str
    kind: Literal["exec", "http"] = "exec"
    timeout: float | None = None  # http only: shown as curl --max-time

    @property
    def url(self) -> str:
        """The URL of an http Command (its only argv element)."""
        if self.kind != "http":
            raise ValueError("only http commands have a url")
        return self.argv[0]

    def display(self) -> str:
        if self.kind == "http":
            max_time = f"{self.timeout:g}" if self.timeout is not None else "10"
            return shlex.join(["curl", "-sS", "--max-time", max_time, self.url])
        return shlex.join(self.argv)

    def to_dict(self) -> dict:
        return {
            "argv": list(self.argv),
            "display": self.display(),
            "purpose": self.purpose,
            "kind": self.kind,
        }


def http_command(url: str, purpose: str, timeout: float) -> Command:
    return Command((url,), purpose, "http", timeout)


def set_command_hook(fn: CommandHook | None) -> None:
    """Call ``fn(cmd)`` right before every exec and every router/speed HTTP request."""
    global _hook
    _hook = fn


def notify(cmd: Command) -> None:
    if _hook is not None:
        _hook(cmd)


def run_command(
    cmd: Command, timeout: float, env: Mapping[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    """Notify the hook, then run exactly ``cmd.argv`` (no shell).

    ``env`` replaces the process environment when set. Callers that need a
    scrubbed environment (git) pass one. Other commands inherit the current
    environment.
    """
    if cmd.kind != "exec":
        raise ValueError("not an exec command")
    notify(cmd)
    kwargs: dict[str, object] = {
        "capture_output": True,
        "text": True,
        "timeout": timeout,
        "check": False,
        "shell": False,
    }
    if env is not None:
        kwargs["env"] = dict(env)
    return subprocess.run(list(cmd.argv), **kwargs)  # noqa: S603 - argv from Command


def emit(callback: Callable[..., None] | None, *args: object) -> None:
    """Call a progress/step callback; its exceptions never break the caller."""
    if callback is None:
        return
    try:
        callback(*args)
    except Exception:  # noqa: BLE001, S110 - a broken UI callback must not stop a scan
        pass


def stream_command(
    cmd: Command, timeout: float, on_line: Callable[[str], None]
) -> subprocess.CompletedProcess:
    """Like :func:`run_command`, but streams stderr lines to ``on_line``.

    stdout is collected in full (nmap's ``-oX -`` XML). Same argv, no shell;
    on timeout the process is killed and ``TimeoutExpired`` is raised.
    """
    import threading

    if cmd.kind != "exec":
        raise ValueError("not an exec command")
    notify(cmd)
    out: list[str] = []
    err: list[str] = []
    with subprocess.Popen(  # noqa: S603 - argv from a build_*_command function
        list(cmd.argv),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        shell=False,
    ) as proc:  # closes both pipes and waits on exit, whatever happens

        def read_stdout() -> None:
            out.append(proc.stdout.read() or "")

        def read_stderr() -> None:
            for line in proc.stderr:
                err.append(line)
                cleaned = clean_text(line.rstrip("\n"))  # core never emits control chars
                if cleaned:
                    emit(on_line, cleaned)

        readers = [
            threading.Thread(target=read_stdout, daemon=True),
            threading.Thread(target=read_stderr, daemon=True),
        ]
        for t in readers:
            t.start()
        try:
            returncode = proc.wait(timeout=timeout)
        except BaseException:  # timeout, KeyboardInterrupt, anything: never leave nmap running
            proc.kill()
            proc.wait()
            raise
        finally:
            for t in readers:
                t.join(timeout=1)
    return subprocess.CompletedProcess(list(cmd.argv), returncode, "".join(out), "".join(err))


# ---- planners: same validation as the real run, but nothing is executed ----


def plan_scan(
    target=None,
    *,
    local_network=None,
    force: bool = False,
    mode: str = "ping",
    top_ports: int = 100,
    stats_every: int | None = None,
    geteuid=None,
    read_text=None,
) -> list[Command]:
    """The nmap sweep used by devices, device, baseline and new-devices."""
    import ipaddress

    from homenet.core.runner import (
        InvalidTargetError,
        TargetNotAllowedError,
        build_scan_command,
        privileged_for,
    )

    target = target if target is not None else local_network
    if target is None:
        raise TargetNotAllowedError(
            "Could not detect your local network.",
            "Check you are connected (see `homenet whoami-net`) or give a subnet to scan.",
        )
    try:
        net = str(ipaddress.ip_network(target, strict=False))
    except ValueError as exc:
        raise InvalidTargetError(
            f"{target!r} is not a valid IP address or subnet.",
            "Use an IP address or subnet like 192.168.1.0/24.",
        ) from exc
    return [
        build_scan_command(
            net,
            mode,
            top_ports,
            local_network=local_network,
            force=force,
            privileged=privileged_for(mode, geteuid, read_text),
            stats_every=stats_every,
        )
    ]


def plan_ports(
    target=None,
    *,
    local_network=None,
    top_ports: int = 100,
    stats_every: int | None = None,
    local: bool = False,
) -> list[Command]:
    if local:
        from homenet.core.local_ports import plan_local_ports

        return plan_local_ports()
    from homenet.core.ports import build_ports_command

    return [
        build_ports_command(
            target, top_ports=top_ports, local_network=local_network, stats_every=stats_every
        )
    ]


def plan_services(
    target=None,
    *,
    local_network=None,
    top_ports: int = 100,
    allow_subnet: bool = False,
    stats_every: int | None = None,
) -> list[Command]:
    from homenet.core.ports import build_services_command

    return [
        build_services_command(
            target,
            top_ports=top_ports,
            local_network=local_network,
            allow_subnet=allow_subnet,
            stats_every=stats_every,
        )
    ]


def plan_whoami() -> list[Command]:
    from homenet.core.netinfo import WHOAMI_IP_ARGS, build_ip_command

    return [build_ip_command(args) for args in WHOAMI_IP_ARGS]


def plan_doctor(gateway: str | None = None, *, which=None, read_text=None) -> list[Command]:
    from homenet.core.checks import plan_check_commands

    return plan_check_commands(gateway, which=which, read_text=read_text)


def plan_router(gateway=None, *, local_network=None, timeout: float | None = None) -> list[Command]:
    from homenet.core.router import DEFAULT_TIMEOUT, build_router_commands

    return build_router_commands(
        gateway, local_network, DEFAULT_TIMEOUT if timeout is None else timeout
    )


def plan_speed(
    *,
    connections: int | None = None,
    nbytes: int | None = None,
    timeout: float | None = None,
    url: str | None = None,
) -> list[Command]:
    """One request per parallel connection (each is re-requested until time is up)."""
    from homenet.core import speed

    n = speed.DEFAULT_CONNECTIONS if connections is None else connections
    if not 1 <= n <= speed.MAX_CONNECTIONS:
        raise speed.SpeedError("The speed test settings are out of range.")
    cmd = speed.build_speed_command(
        nbytes=speed.DEFAULT_BYTES if nbytes is None else nbytes,
        timeout=speed.DEFAULT_TIMEOUT if timeout is None else timeout,
        url=url,
    )
    return [cmd] * n


def plan_wifi(
    iface: str | None = None,
    *,
    connection: str | None = None,
    which=None,
    listdir=None,
    exists=None,
) -> list[Command]:
    from homenet.core.wifi import plan_wifi_commands

    return plan_wifi_commands(
        iface, connection=connection, which=which, listdir=listdir, exists=exists
    )


def plan_dns(*, which=None) -> list[Command]:
    from homenet.core.dns import plan_dns_commands

    return plan_dns_commands(which)


def plan_uninstall() -> list[Command]:
    """The pip or pipx uninstall for this install. Raises if nothing may run."""
    from homenet.core.selfinstall import plan_uninstall as _plan_uninstall

    return _plan_uninstall()


_PLANNERS: dict[str, Callable[..., list[Command]]] = {
    "devices": plan_scan,
    "device": plan_scan,
    "baseline": plan_scan,
    "new-devices": plan_scan,
    "ports": plan_ports,
    "services": plan_services,
    "whoami-net": plan_whoami,
    "doctor": plan_doctor,
    "router": plan_router,
    "speed": plan_speed,
    "wifi": plan_wifi,
    "dns": plan_dns,
    "uninstall": plan_uninstall,
}


def planned_commands(command: str, **params) -> list[Command]:
    """Commands the CLI ``command`` would run, validated but not executed."""
    try:
        planner = _PLANNERS[command]
    except KeyError:
        raise ValueError(
            f"Unknown command {command!r}; expected one of {', '.join(_PLANNERS)}."
        ) from None
    return planner(**params)


__all__: Sequence[str] = (
    "Command",
    "set_command_hook",
    "run_command",
    "plan_scan",
    "plan_ports",
    "plan_services",
    "plan_whoami",
    "plan_doctor",
    "plan_router",
    "plan_speed",
    "plan_wifi",
    "plan_dns",
    "plan_uninstall",
    "planned_commands",
)

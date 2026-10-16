"""DNS configuration and a bounded lookup test. Never prints or exits.

``resolvectl status`` first (real upstream servers per link), falling back to
``/etc/resolv.conf``. 127.0.0.53/54 in resolv.conf means the systemd-resolved stub.
"""

from __future__ import annotations

import ipaddress
import queue
import re
import shutil
import socket
import subprocess  # noqa: S404 - only via commands.run_command (argv, no shell)
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from homenet.core._text import clean_text
from homenet.core.commands import Command, emit, notify, run_command

DEFAULT_TIMEOUT = 5.0
LOOKUP_TIMEOUT = 3.0
STUB_ADDRESSES = frozenset({"127.0.0.53", "127.0.0.54"})
_NAME = re.compile(r"(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?")


@dataclass(frozen=True)
class DnsServer:
    ip: str
    source: str  # "resolvectl" | "resolv.conf"
    interface: str | None = None


@dataclass
class DnsConfig:
    servers: list[DnsServer] = field(default_factory=list)
    source: str | None = None  # where ``servers`` came from
    uses_systemd_stub: bool = False
    upstream: list[str] = field(default_factory=list)  # real servers behind the stub


@dataclass(frozen=True)
class LookupResult:
    name: str
    ok: bool
    addresses: tuple[str, ...] = ()
    elapsed_ms: float | None = None
    error: str | None = None


def _ip(token: str) -> str | None:
    """Validated IP text (drops %scope and #SNI suffixes), else None."""
    base = token.split("#", 1)[0].split("%", 1)[0]
    try:
        return str(ipaddress.ip_address(base))
    except ValueError:
        return None


_KEY = re.compile(r"^\s*([A-Za-z][A-Za-z .]*?):\s*(.*)$")


def parse_resolvectl(text: str) -> list[DnsServer]:
    """Servers from ``resolvectl status`` (Global + each ``Link N (iface)``).

    Multi-line ``DNS Servers:`` lists (continuation lines) are supported.
    """
    servers: list[DnsServer] = []
    iface: str | None = None
    in_list = False
    for raw in (text or "").splitlines():
        if raw.startswith("Global"):
            iface, in_list = None, False
            continue
        if m := re.match(r"Link \d+ \(([^)]+)\)", raw):
            iface, in_list = clean_text(m.group(1), 32), False
            continue
        if m := _KEY.match(raw):
            in_list = m.group(1).strip() == "DNS Servers"
            tokens = m.group(2).split() if in_list else []
        elif in_list:
            tokens = raw.split()
        else:
            continue
        for tok in tokens:
            ip = _ip(tok)
            if ip and not any(s.ip == ip and s.interface == iface for s in servers):
                servers.append(DnsServer(ip, "resolvectl", iface))
    return servers


def parse_resolv_conf(text: str) -> list[DnsServer]:
    out = []
    for line in (text or "").splitlines():
        parts = line.split("#", 1)[0].split()
        if len(parts) >= 2 and parts[0] == "nameserver" and (ip := _ip(parts[1])):
            out.append(DnsServer(ip, "resolv.conf"))
    return out


def build_resolvectl_command(path: str | None = None) -> Command:
    return Command((path or "resolvectl", "status", "--no-pager"), "read the DNS servers in use")


def plan_dns_commands(which: Callable[[str], str | None] | None = None) -> list[Command]:
    path = (which or shutil.which)("resolvectl")
    return [build_resolvectl_command(path)] if path else []


def get_dns_servers(
    *,
    timeout: float = DEFAULT_TIMEOUT,
    on_step: Callable[[str], None] | None = None,
    which: Callable[[str], str | None] | None = None,
    run: Callable[[Sequence[str]], str] | None = None,
    read_text: Callable[[str], str] | None = None,
) -> DnsConfig:
    """DNS servers in use. Never raises; empty config if nothing is readable."""
    read = read_text or (lambda p: Path(p).read_text(encoding="utf-8"))
    emit(on_step, "Reading /etc/resolv.conf")
    try:
        conf = parse_resolv_conf(read("/etc/resolv.conf"))
    except (OSError, UnicodeError):
        conf = []
    stub = any(s.ip in STUB_ADDRESSES for s in conf)
    resolved: list[DnsServer] = []
    path = (which or shutil.which)("resolvectl")
    if path:
        emit(on_step, "Asking systemd-resolved (resolvectl)")
        cmd = build_resolvectl_command(path)
        try:
            if run is not None:
                notify(cmd)
                out = run(list(cmd.argv))
            else:
                proc = run_command(cmd, timeout)
                out = proc.stdout if proc.returncode == 0 else ""
            resolved = [s for s in parse_resolvectl(out) if s.ip not in STUB_ADDRESSES]
        except (OSError, subprocess.SubprocessError):
            resolved = []
    if resolved:
        return DnsConfig(resolved, "resolvectl", stub, [s.ip for s in resolved])
    return DnsConfig(conf, "resolv.conf" if conf else None, stub, [])


def dns_lookup_test(
    name: str = "example.com",
    *,
    timeout: float = LOOKUP_TIMEOUT,
    on_step: Callable[[str], None] | None = None,
    resolver: Callable[..., list] | None = None,
    clock: Callable[[], float] | None = None,
) -> LookupResult:
    """Resolve ``name`` with getaddrinfo on a daemon thread, bounded by ``timeout``."""
    clock = clock or time.monotonic
    if not _NAME.fullmatch(name or ""):
        return LookupResult(clean_text(name, 64) or "", False, error="not a valid host name")
    resolve = resolver or socket.getaddrinfo
    results: queue.SimpleQueue = queue.SimpleQueue()

    def work() -> None:
        try:
            results.put(("ok", resolve(name, None, type=socket.SOCK_STREAM)))
        except Exception as exc:  # noqa: BLE001 - reported as a failed lookup
            results.put(("error", exc))

    emit(on_step, f"Looking up {name}")
    start = clock()
    threading.Thread(target=work, name="homenet-dns-lookup", daemon=True).start()
    try:
        kind, value = results.get(timeout=max(0.0, timeout))
    except queue.Empty:
        return LookupResult(
            name, False, (), round((clock() - start) * 1000, 1), f"timed out after {timeout:g}s"
        )
    elapsed = round((clock() - start) * 1000, 1)
    if kind == "error":
        msg = clean_text(f"{type(value).__name__}: {value}", 200)
        return LookupResult(name, False, (), elapsed, msg)
    addrs = tuple(dict.fromkeys(str(info[4][0]) for info in value if info and info[4]))
    return LookupResult(name, bool(addrs), addrs, elapsed, None if addrs else "no addresses")

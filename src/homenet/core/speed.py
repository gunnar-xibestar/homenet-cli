"""Measure download speed with parallel HTTPS streams from Cloudflare.

One stream under-reports fast links (TCP slow start, WSL2 NAT), so this runs
``connections`` parallel GETs of Cloudflare's ``__down`` endpoint for ``duration``
seconds, re-requesting when a body ends. Bytes are timestamped per chunk; the first
``warmup`` seconds are discarded. TLS verified, no redirects, no proxies, no upload,
no user-supplied address. Daemon threads plus an overall deadline mean a stuck
connection cannot hang the caller. Never prints or exits.
"""

from __future__ import annotations

import queue
import ssl
import statistics
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

from homenet.core._text import clean_text
from homenet.core.commands import Command, emit, http_command, notify

DEFAULT_CONNECTIONS = 4
MAX_CONNECTIONS = 16
DEFAULT_DURATION = 8.0
DEFAULT_WARMUP = 1.0
DEFAULT_BYTES = 25_000_000  # per request; re-requested until time is up
MAX_BYTES = 100_000_000  # per request
DEFAULT_MAX_TOTAL = 200_000_000  # cap across all connections
DEFAULT_TIMEOUT = 10.0  # per request (connect and each read)
CHUNK = 64 * 1024
DEFAULT_URL = "https://speed.cloudflare.com/__down?bytes={nbytes}"

FetchFn = Callable[[str, float], Iterable[bytes]]  # (url, timeout) -> body chunks
Clock = Callable[[], float]
ProgressFn = Callable[[float, float, float], None]  # (elapsed_s, total_s, mbps_so_far)


class SpeedError(Exception):
    """The sample could not be measured. ``hint`` is a beginner-friendly fix."""

    def __init__(self, message: str, hint: str | None = None) -> None:
        super().__init__(message)
        self.hint = hint


@dataclass(frozen=True)
class SpeedResult:
    mbps: float  # aggregate over the post-warmup window
    bytes: int  # bytes counted in that window
    seconds: float  # length of that window
    url: str | None = None
    median_mbps: float | None = None  # median of full per-second samples
    connections: int = 1
    warmup_s: float = 0.0
    errors: tuple[str, ...] = ()
    wsl: bool = False
    total_bytes: int = 0  # everything downloaded, warmup included

    @property
    def download_mbps(self) -> float:  # name used by the CLI output
        return self.mbps

    @property
    def bytes_read(self) -> int:  # name used by the CLI output
        return self.bytes


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # never leave the sample URL
        return None


def build_speed_opener() -> urllib.request.OpenerDirector:
    """HTTPS only, TLS verified, no redirects, and no proxies."""
    context = ssl.create_default_context()
    return urllib.request.build_opener(
        _NoRedirect(),
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context),
    )


def _require_https(url: str) -> None:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise SpeedError(
            "The speed check only downloads from an https address.",
            "This is a bug in the speed check; please report it.",
        )
    if parsed.username or parsed.password:
        raise SpeedError(
            "The speed check does not send a username or password.",
            "This is a bug in the speed check; please report it.",
        )


def download_https(url: str, timeout: float, *, opener=None, chunk: int = CHUNK) -> Iterator[bytes]:
    """GET ``url`` and yield body chunks of up to ``chunk`` bytes. Raises :class:`SpeedError`."""
    _require_https(url)
    opener = opener or build_speed_opener()
    req = urllib.request.Request(  # noqa: S310 - scheme checked above; fixed sample URL
        url, method="GET", headers={"User-Agent": "homenet-cli"}
    )
    try:
        resp = opener.open(req, timeout=max(0.0, timeout))
    except urllib.error.HTTPError as exc:
        raise SpeedError(
            f"The speed sample returned HTTP {exc.code}.",
            "Try again in a moment. If it keeps failing, run `homenet doctor`.",
        ) from exc
    with resp:
        status = getattr(resp, "status", None)
        if status != 200:
            raise SpeedError(
                f"The speed sample returned HTTP {status}.",
                "Try again in a moment. If it keeps failing, run `homenet doctor`.",
            )
        while data := resp.read(chunk):
            yield data


def _read_wsl(read_text: Callable[[str], str] | None) -> bool:
    read = read_text or (lambda p: Path(p).read_text(encoding="utf-8", errors="replace"))
    try:
        return "microsoft" in read("/proc/version").lower()
    except OSError:
        return False


def build_speed_command(
    *, nbytes: int = DEFAULT_BYTES, timeout: float = DEFAULT_TIMEOUT, url: str | None = None
) -> Command:
    """Validated HTTPS sample Command. Runs nothing."""
    if nbytes < 1 or nbytes > MAX_BYTES:
        raise SpeedError(
            f"A speed sample must be between 1 and {MAX_BYTES} bytes.",
            "This is a bug in the speed check; please report it.",
        )
    sample = url if url is not None else DEFAULT_URL.format(nbytes=nbytes)
    _require_https(sample)
    return http_command(sample, f"download {nbytes} bytes to estimate speed", timeout)


@dataclass
class _State:
    start: float
    warm_end: float
    end: float
    cap: int
    lock: threading.Lock = field(default_factory=threading.Lock)
    stop: threading.Event = field(default_factory=threading.Event)
    samples: list[tuple[float, int]] = field(default_factory=list)
    total: int = 0
    post: int = 0
    last: float = 0.0
    errors: list[str] = field(default_factory=list)


def _mbps(nbytes: int, seconds: float) -> float:
    return round(nbytes * 8 / seconds / 1_000_000, 2) if seconds > 0 else 0.0


def _worker(
    st: _State,
    cmd: Command,
    fetch: FetchFn,
    clock: Clock,
    ticks: queue.SimpleQueue,
    duration: float,
    next_tick: list[float],
) -> None:
    while not st.stop.is_set():
        notify(cmd)  # one hook call per request, same Command as plan_speed
        try:
            got = 0
            for chunk in fetch(cmd.url, cmd.timeout):
                now = clock()
                with st.lock:
                    n = min(len(chunk), st.cap - st.total)
                    if n > 0 and now <= st.end:
                        st.samples.append((now, n))
                        st.total += n
                        st.last = max(st.last, now)
                        if now >= st.warm_end:
                            st.post += n
                        got += n
                    while now >= next_tick[0] and next_tick[0] <= st.end:
                        window = min(now, st.end) - st.warm_end
                        ticks.put(
                            (
                                round(next_tick[0] - st.start, 3),
                                duration,
                                _mbps(st.post, window) if window > 0 else 0.0,
                            )
                        )
                        next_tick[0] += 1.0
                    if st.total >= st.cap:
                        st.stop.set()  # byte cap: every connection stops
                if st.stop.is_set() or now >= st.end:
                    return
            if got == 0:  # empty body: don't spin
                raise SpeedError("The speed sample came back empty.")
        except Exception as exc:  # noqa: BLE001 - this connection stops; others continue
            with st.lock:
                st.errors.append(clean_text(f"{type(exc).__name__}: {exc}", 200) or "error")
            return


def measure_download(
    *,
    connections: int = DEFAULT_CONNECTIONS,
    duration: float = DEFAULT_DURATION,
    warmup: float = DEFAULT_WARMUP,
    max_bytes: int = DEFAULT_MAX_TOTAL,
    nbytes: int = DEFAULT_BYTES,
    timeout: float = DEFAULT_TIMEOUT,
    url: str | None = None,
    on_progress: ProgressFn | None = None,
    fetch: FetchFn | None = None,
    clock: Clock | None = None,
    read_text: Callable[[str], str] | None = None,
) -> SpeedResult:
    """Parallel download test; returns decimal megabits per second.

    ``on_progress(elapsed_s, total_s, mbps_so_far)`` is called about once a second
    on the caller's thread (``mbps_so_far`` is 0.0 during warmup). ``fetch``,
    ``clock`` and ``read_text`` are injectable so tests never touch the network.
    """
    if not 1 <= connections <= MAX_CONNECTIONS or duration <= 0 or not 0 <= warmup < duration:
        raise SpeedError(
            "The speed test settings are out of range.",
            "This is a bug in the speed check; please report it.",
        )
    if max_bytes < 1:
        raise SpeedError(
            "The speed test byte cap must be positive.",
            "This is a bug in the speed check; please report it.",
        )
    cmd = build_speed_command(nbytes=nbytes, timeout=timeout, url=url)
    fetch = fetch or download_https
    clock = clock or time.perf_counter
    wsl = _read_wsl(read_text)
    start = clock()
    st = _State(start, start + warmup, start + duration, max_bytes)
    ticks: queue.SimpleQueue = queue.SimpleQueue()
    next_tick = [start + 1.0]
    workers = [
        threading.Thread(
            target=_worker,
            args=(st, cmd, fetch, clock, ticks, duration, next_tick),
            name=f"homenet-speed-{i}",
            daemon=True,
        )
        for i in range(connections)
    ]
    for w in workers:
        w.start()
    hard_deadline = time.monotonic() + duration + timeout  # real time, even with a fake clock

    def drain() -> None:
        while True:
            try:
                tick = ticks.get_nowait()
            except queue.Empty:
                return
            emit(on_progress, *tick)

    while any(w.is_alive() for w in workers) and time.monotonic() < hard_deadline:
        st.stop.wait(0.1)
        drain()
        if st.stop.is_set():
            break
    st.stop.set()
    for w in workers:
        w.join(max(0.0, min(1.0, hard_deadline - time.monotonic())))
    drain()
    with st.lock:
        samples, total, errors, last = list(st.samples), st.total, tuple(st.errors), st.last
    if not total:
        raise SpeedError(
            "Could not measure your internet speed.",
            "Check that this computer can reach the internet, then try `homenet speed` again.",
        )
    end = min(last, st.end)
    post = [(t, n) for t, n in samples if t >= st.warm_end]
    if post and end > st.warm_end:
        window_start, counted = st.warm_end, post
    else:  # too short to skip warmup: use everything
        window_start, counted = start, samples
    seconds = round(max(end - window_start, 0.001), 3)
    nbytes_counted = sum(n for _, n in counted)
    buckets = [0] * int(end - window_start)  # full seconds only
    for t, n in counted:
        k = int(t - window_start)
        if k < len(buckets):
            buckets[k] += n
    median = round(statistics.median(b * 8 / 1_000_000 for b in buckets), 2) if buckets else None
    return SpeedResult(
        _mbps(nbytes_counted, seconds),
        nbytes_counted,
        seconds,
        cmd.url,
        median,
        connections,
        warmup if counted is post else 0.0,
        errors,
        wsl,
        total,
    )

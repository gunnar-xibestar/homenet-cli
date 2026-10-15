"""Time one short HTTPS download and report megabits per second.

Core has no speed test. This is a bounded sample, not a full measurement:
one GET of a fixed Cloudflare URL, TLS verified, no redirects, no proxies,
and no user-supplied address. A daemon thread caps the wait so a stuck
connection cannot hang the caller. Never prints or exits.
"""

from __future__ import annotations

import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass

DEFAULT_BYTES = 1_000_000
MAX_BYTES = 2_000_000
DEFAULT_TIMEOUT = 20.0
DEFAULT_URL = "https://speed.cloudflare.com/__down?bytes={nbytes}"

FetchFn = Callable[[str, float, int], bytes]  # (url, timeout, max_bytes) -> body
Clock = Callable[[], float]


class SpeedError(Exception):
    """The sample could not be measured. ``hint`` is a beginner-friendly fix."""

    def __init__(self, message: str, hint: str | None = None) -> None:
        super().__init__(message)
        self.hint = hint


@dataclass(frozen=True)
class SpeedResult:
    download_mbps: float
    bytes_read: int
    seconds: float
    url: str


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


def download_https(url: str, timeout: float, max_bytes: int, *, opener=None) -> bytes:
    """GET ``url`` and return at most ``max_bytes``. Raises :class:`SpeedError`."""
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
        return resp.read(max_bytes) or b""


def _run_bounded(fetch: FetchFn, url: str, timeout: float, nbytes: int) -> bytes:
    """Run ``fetch`` on a daemon thread and give up after ``timeout`` seconds."""
    box: dict = {}

    def run() -> None:
        try:
            box["result"] = fetch(url, timeout, nbytes)
        except Exception as exc:  # noqa: BLE001 - report it as a failed sample
            box["error"] = exc

    worker = threading.Thread(target=run, name="homenet-speed", daemon=True)
    worker.start()
    worker.join(max(0.0, timeout))
    if worker.is_alive():
        raise SpeedError(
            "The speed check timed out.",
            "Check that this computer can reach the internet, then try again.",
        )
    if "error" in box:
        raise box["error"]
    return box.get("result")


def measure_download(
    *,
    nbytes: int = DEFAULT_BYTES,
    timeout: float = DEFAULT_TIMEOUT,
    url: str | None = None,
    fetch: FetchFn | None = None,
    clock: Clock | None = None,
) -> SpeedResult:
    """Download ``nbytes`` and return decimal megabits per second.

    ``fetch`` and ``clock`` are injectable so tests never touch the network.
    The default URL is Cloudflare's fixed-size download endpoint.
    """
    if nbytes < 1 or nbytes > MAX_BYTES:
        raise SpeedError(
            f"A speed sample must be between 1 and {MAX_BYTES} bytes.",
            "This is a bug in the speed check; please report it.",
        )
    sample = url if url is not None else DEFAULT_URL.format(nbytes=nbytes)
    _require_https(sample)
    fetch = fetch or download_https
    clock = clock or time.perf_counter
    start = clock()
    try:
        data = _run_bounded(fetch, sample, timeout, nbytes)
    except SpeedError:
        raise
    except (OSError, urllib.error.URLError) as exc:
        raise SpeedError(
            "Could not measure your internet speed.",
            "Check that this computer can reach the internet, then try `homenet speed` again.",
        ) from exc
    if not isinstance(data, (bytes, bytearray)):
        raise SpeedError(
            "The speed sample was not usable.",
            "Try again. If it keeps failing, run `homenet doctor`.",
        )
    payload = bytes(data)[:nbytes]
    if not payload:
        raise SpeedError(
            "The speed sample came back empty.",
            "Try again in a moment. If it keeps failing, run `homenet doctor`.",
        )
    seconds = round(max(clock() - start, 0.001), 3)
    mbps = round((len(payload) * 8) / seconds / 1_000_000, 2)
    return SpeedResult(mbps, len(payload), seconds, sample)

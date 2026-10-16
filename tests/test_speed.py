"""Parallel download-speed test. The fetch is injected; nothing here touches the network."""

from __future__ import annotations

import ssl
import threading
import time
import urllib.error
import urllib.request

import pytest

from homenet.core.commands import plan_speed, set_command_hook
from homenet.core.speed import (
    SpeedError,
    _NoRedirect,
    build_speed_opener,
    download_https,
    measure_download,
)


class _Body:
    def __init__(self, data: bytes, status: int = 200) -> None:
        self.data = data
        self.status = status
        self.read_arg = None

    def read(self, n: int) -> bytes:
        self.read_arg = n
        out, self.data = self.data[:n], self.data[n:]
        return out

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class _Opener:
    def __init__(self, resp) -> None:
        self.resp = resp
        self.req = None
        self.timeout = None

    def open(self, req, timeout):
        self.req = req
        self.timeout = timeout
        if isinstance(self.resp, Exception):
            raise self.resp
        return self.resp


class FakeClock:
    """Per-thread timeline: each connection advances its own time, so runs are exact."""

    def __init__(self) -> None:
        self.local = threading.local()

    def __call__(self) -> float:
        return getattr(self.local, "t", 0.0)

    def fetcher(
        self, *, chunk=156_250, dt=0.125, slow_until=0.0, per_request=None, fail_first=False
    ):
        """10 Mbps chunks (1 Mbps before ``slow_until``); ``per_request`` chunks per body."""
        calls = []
        lock = threading.Lock()

        def fetch(url, timeout):
            with lock:
                calls.append(url)
                first = len(calls) == 1
            if fail_first and first:
                raise OSError("boom")
            n = 0
            while per_request is None or n < per_request:
                self.local.t = self() + dt
                n += 1
                yield b"x" * (chunk // 10 if self() < slow_until else chunk)

        fetch.calls = calls
        return fetch


def run(clock, fetch, **kw):
    kw.setdefault("read_text", lambda p: "Linux version 6.6")
    return measure_download(fetch=fetch, clock=clock, **kw)


def test_warmup_is_excluded_and_median_is_per_second():
    clock = FakeClock()
    r = run(clock, clock.fetcher(slow_until=1.0), connections=1, duration=4, warmup=1)
    assert (r.mbps, r.median_mbps, r.seconds, r.warmup_s) == (10.42, 10.0, 3.0, 1.0)
    assert r.bytes == 25 * 156_250 and r.total_bytes == r.bytes + 7 * 15_625
    assert (r.download_mbps, r.bytes_read, r.errors, r.wsl) == (r.mbps, r.bytes, (), False)


def test_progress_ticks_once_a_second_and_callback_errors_are_swallowed():
    clock, ticks = FakeClock(), []

    def on_progress(*tick):
        ticks.append(tick)
        raise RuntimeError("UI broke")

    r = run(clock, clock.fetcher(), connections=1, duration=4, warmup=1, on_progress=on_progress)
    assert [t[:2] for t in ticks] == [(1.0, 4), (2.0, 4), (3.0, 4), (4.0, 4)]
    assert ticks[0][2] == 0.0 and ticks[-1][2] == r.mbps


def test_aggregates_across_connections_and_hook_sees_each_request():
    clock, seen = FakeClock(), []
    set_command_hook(seen.append)
    try:
        r = run(
            clock,
            clock.fetcher(per_request=4),
            connections=3,
            duration=2,
            warmup=0,
            read_text=lambda p: "Linux 5.15-microsoft-standard-WSL2",
        )
    finally:
        set_command_hook(None)
    assert (r.mbps, r.connections, r.wsl) == (30.0, 3, True)
    planned = plan_speed(connections=3)
    assert len(seen) == 12 and {c.url for c in seen} == {planned[0].url} and len(planned) == 3


def test_total_byte_cap_stops_all_connections():
    clock = FakeClock()
    r = run(clock, clock.fetcher(), connections=2, duration=8, warmup=0, max_bytes=1_000_000)
    assert r.total_bytes == 1_000_000 and r.seconds < 8


def test_deadline_stops_and_bodies_are_re_requested():
    clock = FakeClock()
    fetch = clock.fetcher(per_request=4)
    r = run(clock, fetch, connections=2, duration=3, warmup=0)
    assert r.seconds == 3.0 and r.mbps == 20.0 and len(fetch.calls) == 12


def test_hung_connection_hits_the_real_deadline():
    release = threading.Event()

    def stalls_mid_body(url, timeout):
        yield b"x" * 1000
        release.wait(5)
        yield b"y"

    start = time.monotonic()
    r = measure_download(
        fetch=stalls_mid_body,
        connections=1,
        duration=0.2,
        warmup=0,
        timeout=0.2,
        read_text=lambda p: "",
    )
    release.set()
    assert time.monotonic() - start < 2 and r.total_bytes == 1000


def test_one_failing_connection_does_not_stop_the_others():
    clock = FakeClock()
    r = run(clock, clock.fetcher(fail_first=True), connections=3, duration=2, warmup=0)
    assert (r.mbps, r.errors) == (20.0, ("OSError: boom",))


@pytest.mark.parametrize(
    "kw", [{"connections": 0}, {"duration": 0}, {"warmup": 8}, {"max_bytes": 0}, {"nbytes": 10**9}]
)
def test_bad_settings_are_rejected_before_fetching(kw):
    with pytest.raises(SpeedError):
        measure_download(fetch=lambda u, t: pytest.fail("fetched"), **kw)


def test_download_https_streams_chunks():
    body = _Body(b"abcdef")
    opener = _Opener(body)
    url = "https://speed.cloudflare.com/__down?bytes=6"
    assert list(download_https(url, 3.0, opener=opener, chunk=4)) == [b"abcd", b"ef"]
    assert body.read_arg == 4
    assert opener.timeout == 3.0
    assert opener.req.get_method() == "GET"
    assert opener.req.get_header("User-agent") == "homenet-cli"


@pytest.mark.parametrize(
    ("url", "resp", "match"),
    [
        ("http://example.com/", _Body(b"x"), "https"),
        (
            "https://speed.cloudflare.com/x",
            urllib.error.HTTPError("https://x", 500, "no", hdrs=None, fp=None),
            "HTTP 500",
        ),
        ("https://speed.cloudflare.com/x", _Body(b"x", 404), "HTTP 404"),
    ],
    ids=["http-url", "http-500", "status-404"],
)
def test_download_https_refuses_http_and_bad_status(url, resp, match):
    opener = _Opener(resp)
    with pytest.raises(SpeedError, match=match):
        list(download_https(url, 1, opener=opener))
    if match == "https":
        assert opener.req is None


def test_speed_opener_verifies_tls_and_ignores_proxy_env(monkeypatch):
    monkeypatch.setenv("http_proxy", "http://127.0.0.1:9")
    monkeypatch.setenv("https_proxy", "http://127.0.0.1:9")
    opener = build_speed_opener()
    usual = urllib.request.build_opener()
    assert any(
        isinstance(handler, urllib.request.ProxyHandler) and handler.proxies
        for handler in usual.handlers
    )
    assert not any(isinstance(handler, urllib.request.ProxyHandler) for handler in opener.handlers)
    https = next(
        handler for handler in opener.handlers if isinstance(handler, urllib.request.HTTPSHandler)
    )
    assert https._context.verify_mode == ssl.CERT_REQUIRED
    assert any(isinstance(handler, _NoRedirect) for handler in opener.handlers)
    assert _NoRedirect().redirect_request() is None

"""Download-speed sample. The fetch is injected; nothing here touches the network."""

from __future__ import annotations

import ssl
import threading
import urllib.error
import urllib.request

import pytest

from homenet.core.speed import (
    DEFAULT_BYTES,
    DEFAULT_TIMEOUT,
    DEFAULT_URL,
    MAX_BYTES,
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
        return self.data[:n]

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


def _clock(*values):
    pending = iter(values)

    def clock() -> float:
        return next(pending)

    return clock


def test_measure_download_reports_decimal_megabits():
    seen = {}

    def fetch(url, timeout, max_bytes):
        seen["url"] = url
        seen["timeout"] = timeout
        seen["max_bytes"] = max_bytes
        return b"x" * max_bytes

    result = measure_download(fetch=fetch, clock=_clock(10.0, 11.0))
    assert seen["url"] == DEFAULT_URL.format(nbytes=DEFAULT_BYTES)
    assert seen["url"].startswith("https://")
    assert seen["timeout"] == DEFAULT_TIMEOUT
    assert seen["max_bytes"] == DEFAULT_BYTES
    assert result.bytes_read == DEFAULT_BYTES
    assert result.seconds == 1.0
    assert result.download_mbps == 8.0


def test_measure_download_caps_the_body_and_a_stuck_clock():
    result = measure_download(
        fetch=lambda *_args: b"z" * 500,
        nbytes=100,
        clock=_clock(5.0, 5.0),
    )
    assert result.bytes_read == 100
    assert result.seconds == 0.001


def test_measure_download_rejects_a_bad_sample_before_fetching():
    def fetch(*_args):
        raise AssertionError("fetch should not run")

    with pytest.raises(SpeedError, match="between 1 and"):
        measure_download(nbytes=0, fetch=fetch)
    with pytest.raises(SpeedError, match="between 1 and"):
        measure_download(nbytes=MAX_BYTES + 1, fetch=fetch)
    with pytest.raises(SpeedError, match="https"):
        measure_download(url="http://example.com/a", fetch=fetch)
    with pytest.raises(SpeedError, match="password"):
        measure_download(url="https://user:secret@example.com/a", fetch=fetch)


def test_measure_download_wraps_network_errors_and_an_empty_body():
    def offline(*_args):
        raise urllib.error.URLError("no route")

    with pytest.raises(SpeedError, match="Could not measure") as exc:
        measure_download(fetch=offline, clock=_clock(0.0, 1.0))
    assert "homenet speed" in exc.value.hint

    with pytest.raises(SpeedError, match="empty") as empty:
        measure_download(fetch=lambda *_args: b"", clock=_clock(0.0, 1.0))
    assert "homenet doctor" in empty.value.hint

    def already(url, timeout, max_bytes):
        raise SpeedError("custom", "keep this hint")

    with pytest.raises(SpeedError, match="custom") as custom:
        measure_download(fetch=already)
    assert custom.value.hint == "keep this hint"


def test_measure_download_times_out_when_the_fetch_sticks():
    started = threading.Event()
    release = threading.Event()

    def fetch(url, timeout, max_bytes):
        started.set()
        release.wait(5)
        return b"x"

    try:
        with pytest.raises(SpeedError, match="timed out") as exc:
            measure_download(fetch=fetch, timeout=0.05, clock=_clock(0.0))
        assert "internet" in exc.value.hint
    finally:
        release.set()
    assert started.wait(1)


def test_download_https_reads_only_the_cap():
    body = _Body(b"abcdef")
    opener = _Opener(body)
    data = download_https("https://speed.cloudflare.com/__down?bytes=4", 3.0, 4, opener=opener)
    assert data == b"abcd"
    assert body.read_arg == 4
    assert opener.timeout == 3.0
    assert opener.req.get_method() == "GET"
    assert opener.req.get_header("User-agent") == "homenet-cli"


def test_download_https_refuses_http_and_bad_status():
    opener = _Opener(_Body(b"x"))
    with pytest.raises(SpeedError, match="https"):
        download_https("http://example.com/", 1, 10, opener=opener)
    assert opener.req is None
    http_error = urllib.error.HTTPError("https://x", 500, "no", hdrs=None, fp=None)
    with pytest.raises(SpeedError, match="HTTP 500"):
        download_https("https://speed.cloudflare.com/x", 1, 10, opener=_Opener(http_error))
    with pytest.raises(SpeedError, match="HTTP 404"):
        download_https("https://speed.cloudflare.com/x", 1, 10, opener=_Opener(_Body(b"x", 404)))


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

"""Check whether the default gateway exposes a web admin page.

A single unauthenticated GET per URL (ports 80, 443, 8080) with a short
timeout. No logins, credentials, form posts or redirect following. TLS
verification is disabled only for these router requests, because home routers
use self-signed certificates. Never prints or exits.
"""

from __future__ import annotations

import html
import http.client
import ipaddress
import json
import re
import ssl
import subprocess  # noqa: S404 - only via netinfo._run_ip (argument lists)
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field

from homenet.core._text import _clean
from homenet.core.devices import detect_local_network
from homenet.core.netinfo import NetInfoError, _run_ip, parse_default_route
from homenet.core.runner import InvalidTargetError, TargetNotAllowedError

ADMIN_URLS = ((80, "http"), (443, "https"), (8080, "http"))
DEFAULT_TIMEOUT = 3.0  # per request
DEFAULT_BUDGET = 8.0  # whole check, all ports
MAX_BODY = 64 * 1024


@dataclass(frozen=True)
class FetchResult:
    status: int
    headers: Mapping[str, str]
    body: str


Fetcher = Callable[[str, float, bool], FetchResult]  # (url, timeout, verify_tls)


@dataclass(frozen=True)
class AdminPage:
    url: str
    port: int
    reachable: bool
    plain_http: bool
    status: int | None = None
    title: str | None = None
    server: str | None = None
    error: str | None = None


@dataclass
class RouterCheck:
    gateway: str
    pages: list[AdminPage] = field(default_factory=list)

    @property
    def admin_reachable(self) -> bool:
        return any(p.reachable for p in self.pages)

    @property
    def plain_http_reachable(self) -> bool:
        return any(p.reachable and p.plain_http for p in self.pages)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # never follow redirects off the router
        return None


def build_router_opener(https: bool, verify_tls: bool) -> urllib.request.OpenerDirector:
    """Opener with no redirects and no proxies; TLS verify off only if asked (router)."""
    handlers: list = [_NoRedirect(), urllib.request.ProxyHandler({})]
    if https:
        ctx = ssl.create_default_context()
        if not verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE  # router self-signed cert; this check only
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    return urllib.request.build_opener(*handlers)


def _read_body(resp) -> str:
    data = resp.read(MAX_BODY) if resp is not None else b""
    return (data or b"")[:MAX_BODY].decode("utf-8", "replace")


def http_get(url: str, timeout: float, verify_tls: bool, *, opener=None) -> FetchResult:
    """Plain GET with no credentials and no redirects. Body capped at 64 KiB."""
    if not url.startswith(("http://", "https://")):
        raise ValueError("only http(s) URLs are allowed")
    opener = opener or build_router_opener(url.startswith("https://"), verify_tls)
    req = urllib.request.Request(  # noqa: S310 - scheme checked above
        url, method="GET", headers={"User-Agent": "homenet-cli"}
    )
    try:
        resp = opener.open(req, timeout=timeout)
    except urllib.error.HTTPError as exc:  # 3xx/4xx/5xx still mean "a page is there"
        body = _read_body(exc) if exc.fp else ""
        return FetchResult(exc.code, dict(exc.headers or {}), body)
    with resp:
        return FetchResult(resp.status, dict(resp.headers), _read_body(resp))


_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def extract_title(body: str) -> str | None:
    m = _TITLE.search(body or "")
    if not m:
        return None
    return _clean(html.unescape(m.group(1)))


def detect_gateway(ip_runner: Callable[[Sequence[str]], str] | None = None) -> str | None:
    """Default gateway from ``ip -j route``, or None."""
    try:
        routes = json.loads((ip_runner or _run_ip)(["-j", "route", "show"]) or "null")
        return parse_default_route(routes)[1]
    except (OSError, subprocess.SubprocessError, ValueError, NetInfoError):
        return None


_FETCH_ERRORS = (OSError, ValueError, ssl.SSLError, http.client.HTTPException)


def _fetch_bounded(
    fetch: Fetcher, url: str, timeout: float, limit: float
) -> tuple[FetchResult | None, str | None]:
    """Run ``fetch`` on a daemon thread; give up after ``limit`` seconds."""
    box: dict = {}

    def run() -> None:
        try:
            box["result"] = fetch(url, timeout, False)
        except _FETCH_ERRORS as exc:
            reason = getattr(exc, "reason", None) or exc
            box["error"] = _clean(f"{type(exc).__name__}: {reason}") or type(exc).__name__
        except Exception as exc:  # noqa: BLE001 - never let a bad router crash the CLI
            box["error"] = _clean(f"unexpected error: {type(exc).__name__}") or "error"

    t = threading.Thread(target=run, name="homenet-router-fetch", daemon=True)
    t.start()
    t.join(max(0.0, limit))
    if t.is_alive():
        return None, "timed out (overall time limit reached)"
    if "error" in box:
        return None, box["error"]
    return box["result"], None


def check_router_admin(
    gateway: str | None = None,
    *,
    local_network: ipaddress.IPv4Network | str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    budget: float = DEFAULT_BUDGET,
    fetch: Fetcher | None = None,
    ip_runner: Callable[[Sequence[str]], str] | None = None,
) -> RouterCheck:
    """GET http://gw/, https://gw/ and http://gw:8080/ and report what answers.

    ``timeout`` bounds each request; ``budget`` bounds the whole check. Each
    fetch runs on a daemon thread, so a stuck connection cannot exceed it.

    The gateway must be inside the default-route subnet; otherwise
    :class:`TargetNotAllowedError` is raised before any request is made.
    """
    local = local_network if local_network is not None else detect_local_network(ip_runner)
    gw = gateway if gateway is not None else detect_gateway(ip_runner)
    if local is None or gw is None:
        raise TargetNotAllowedError(
            "Could not detect your router (default gateway).",
            "Check you are connected (see `homenet whoami-net`).",
        )
    try:
        gw_ip = ipaddress.ip_address(gw)
    except ValueError as exc:
        raise InvalidTargetError(f"{gw!r} is not a valid IP address.") from exc
    local_net = ipaddress.ip_network(local, strict=False)
    if gw_ip.version != 4 or gw_ip not in local_net:
        raise TargetNotAllowedError(
            f"{gw_ip} is outside your local subnet ({local_net}); refusing to contact it.",
            "Only your own router can be checked.",
        )
    fetch = fetch or http_get
    deadline = time.monotonic() + max(0.0, budget)
    result = RouterCheck(str(gw_ip))
    for port, scheme in ADMIN_URLS:
        default = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
        url = f"{scheme}://{gw_ip}/" if default else f"{scheme}://{gw_ip}:{port}/"
        plain = scheme == "http"
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            result.pages.append(
                AdminPage(url, port, False, plain, error="skipped: time limit reached")
            )
            continue
        r, err = _fetch_bounded(fetch, url, min(timeout, remaining), remaining)
        if err is not None:
            result.pages.append(AdminPage(url, port, False, plain, error=err))
            continue
        headers = {str(k).lower(): v for k, v in (r.headers or {}).items()}
        result.pages.append(
            AdminPage(
                url,
                port,
                True,
                plain,
                status=r.status,
                title=extract_title(r.body),
                server=_clean(headers.get("server")),
            )
        )
    return result

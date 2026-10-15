import pytest

from homenet.core.router import (
    FetchResult,
    check_router_admin,
    detect_gateway,
    extract_title,
    http_get,
)
from homenet.core.runner import InvalidTargetError, TargetNotAllowedError

NET = "192.168.1.0/24"


class FakeFetcher:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def __call__(self, url, timeout, verify_tls):
        self.calls.append((url, timeout, verify_tls))
        r = self.responses.get(url)
        if isinstance(r, Exception):
            raise r
        if r is None:
            raise ConnectionRefusedError(111, "Connection refused")
        return r


def test_admin_page_found(load_fixture):
    page = FetchResult(200, {"Server": "lighttpd/1.4"}, load_fixture("router_admin.html"))
    fetch = FakeFetcher(
        {
            "http://192.168.1.1/": page,
            "https://192.168.1.1/": FetchResult(401, {"server": "lighttpd"}, ""),
            "http://192.168.1.1:8080/": TimeoutError("timed out"),
        }
    )
    r = check_router_admin("192.168.1.1", local_network=NET, fetch=fetch, timeout=1.5)
    assert [c[0] for c in fetch.calls] == [
        "http://192.168.1.1/",
        "https://192.168.1.1/",
        "http://192.168.1.1:8080/",
    ]
    assert all(c[1] == 1.5 and c[2] is False for c in fetch.calls)
    http, https, alt = r.pages
    assert http.reachable and http.plain_http and http.title == "TP-Link & Router Login"
    assert http.server == "lighttpd/1.4" and http.status == 200
    assert https.reachable and not https.plain_http and https.status == 401
    assert not alt.reachable and "timed out" in alt.error
    assert r.admin_reachable and r.plain_http_reachable


def test_nothing_reachable():
    r = check_router_admin("192.168.1.1", local_network=NET, fetch=FakeFetcher({}))
    assert not r.admin_reachable and not r.plain_http_reachable
    assert all(p.error for p in r.pages)


def test_https_only():
    fetch = FakeFetcher({"https://192.168.1.1/": FetchResult(200, {}, "<title>Hi</title>")})
    r = check_router_admin("192.168.1.1", local_network=NET, fetch=fetch)
    assert r.admin_reachable and not r.plain_http_reachable


@pytest.mark.parametrize("gw", ["10.0.0.1", "8.8.8.8", "172.17.0.1", "192.168.2.1"])
def test_outside_local_refused_before_any_request(gw):
    fetch = FakeFetcher({})
    with pytest.raises(TargetNotAllowedError):
        check_router_admin(gw, local_network=NET, fetch=fetch)
    assert fetch.calls == []


def test_invalid_gateway():
    with pytest.raises(InvalidTargetError):
        check_router_admin("router.lan; rm", local_network=NET, fetch=FakeFetcher({}))


def test_detects_gateway_and_subnet(load_fixture):
    def ip_runner(args):
        return load_fixture("ip_route.json" if args[1] == "route" else "ip_addr.json")

    assert detect_gateway(ip_runner) == "192.168.1.1"
    fetch = FakeFetcher({})
    assert check_router_admin(fetch=fetch, ip_runner=ip_runner).gateway == "192.168.1.1"
    assert len(fetch.calls) == 3


def test_no_gateway():
    with pytest.raises(TargetNotAllowedError, match="Could not detect"):
        check_router_admin(fetch=FakeFetcher({}), ip_runner=lambda a: "[]")


@pytest.mark.parametrize(
    ("body", "title"),
    [
        ("<TITLE>Admin</TITLE>", "Admin"),
        ("<title>\n a \n b </title>", "a b"),
        ("", None),
        ("<html>no title</html>", None),
        ("<title></title>", None),
    ],
)
def test_extract_title(body, title):
    assert extract_title(body) == title


def test_http_get_rejects_other_schemes():
    with pytest.raises(ValueError):
        http_get("file:///etc/passwd", 1, False)


# ---- review fixes ----
import http.client  # noqa: E402
import io  # noqa: E402
import threading  # noqa: E402
import time  # noqa: E402
import urllib.error  # noqa: E402
import urllib.request  # noqa: E402

from homenet.core import router as rt  # noqa: E402


@pytest.mark.parametrize(
    "exc",
    [
        http.client.BadStatusLine("garbage"),
        http.client.IncompleteRead(b"x", 10),
        http.client.RemoteDisconnected("closed"),
        http.client.LineTooLong("header"),
    ],
)
def test_http_exceptions_become_page_errors(exc):
    fetch = FakeFetcher({"http://192.168.1.1/": exc})
    r = check_router_admin("192.168.1.1", local_network=NET, fetch=fetch)
    assert not r.pages[0].reachable and type(exc).__name__ in r.pages[0].error


def test_unexpected_exception_is_contained():
    fetch = FakeFetcher({"http://192.168.1.1/": RuntimeError("boom")})
    r = check_router_admin("192.168.1.1", local_network=NET, fetch=fetch)
    assert r.pages[0].error.startswith("unexpected error")


def test_title_and_server_are_sanitized():
    body = "<title>Router \x1b[2J\n  Login</title>"
    fetch = FakeFetcher(
        {"http://192.168.1.1/": FetchResult(200, {"Server": "httpd\x1b[1m\r\nX: 1"}, body)}
    )
    page = check_router_admin("192.168.1.1", local_network=NET, fetch=fetch).pages[0]
    assert (page.title, page.server) == ("Router ?[2J Login", "httpd?[1m??X: 1")


def test_service_banners_sanitized():
    from homenet.core.parser import parse_nmap_xml

    xml = (
        '<nmaprun><host><status state="up"/><address addr="192.168.1.9" addrtype="ipv4"/>'
        '<ports><port protocol="tcp" portid="22"><state state="open"/>'
        '<service name="ssh" product="Open&#x9b;[2JSSH" version="9&#x202e;.2&#x9;"/></port>'
        "</ports></host></nmaprun>"
    )
    (dev,) = parse_nmap_xml(xml)
    assert (dev.ports[0].product, dev.ports[0].version) == ("Open?[2JSSH", "9?.2?")


# http_get with a fake opener


class FakeResp(io.BytesIO):
    def __init__(self, data, status=200, headers=None):
        super().__init__(data)
        self.status = status
        self.headers = headers or {}
        self.read_sizes = []

    def read(self, n=-1):
        self.read_sizes.append(n)
        return super().read(n)


class FakeOpener:
    def __init__(self, resp=None, exc=None):
        self.resp, self.exc, self.requests = resp, exc, []

    def open(self, req, timeout):
        self.requests.append((req, timeout))
        if self.exc:
            raise self.exc
        return self.resp


def test_http_get_caps_body():
    resp = FakeResp(b"x" * (rt.MAX_BODY * 3), headers={"Server": "s"})
    opener = FakeOpener(resp)
    r = rt.http_get("http://192.168.1.1/", 2, False, opener=opener)
    assert len(r.body) == rt.MAX_BODY and resp.read_sizes == [rt.MAX_BODY]
    req, timeout = opener.requests[0]
    assert req.get_method() == "GET" and timeout == 2
    assert req.data is None and "Authorization" not in req.headers


def test_http_get_error_responses():
    err = urllib.error.HTTPError(
        "http://192.168.1.1/", 401, "Unauthorized", {"Server": "mini"}, io.BytesIO(b"denied")
    )
    r = rt.http_get("http://192.168.1.1/", 1, False, opener=FakeOpener(exc=err))
    assert (r.status, r.headers["Server"], r.body) == (401, "mini", "denied")


def test_http_get_redirect_not_followed():
    # The real opener never follows redirects: the handler refuses them.
    opener = rt.build_router_opener(https=False, verify_tls=False)
    assert any(isinstance(h, rt._NoRedirect) for h in opener.handlers)
    assert rt._NoRedirect().redirect_request(None, None, 302, "Found", {}, "http://evil/") is None
    # A 302 surfaces as an HTTPError response with its Location, not a second request.
    err = urllib.error.HTTPError(
        "http://192.168.1.1/", 302, "Found", {"Location": "http://8.8.8.8/"}, io.BytesIO(b"")
    )
    fake = FakeOpener(exc=err)
    r = rt.http_get("http://192.168.1.1/", 1, False, opener=fake)
    assert r.status == 302 and r.headers["Location"] == "http://8.8.8.8/"
    assert len(fake.requests) == 1


def test_router_opener_tls_settings():
    import ssl

    def ctx(opener):
        (h,) = [h for h in opener.handlers if isinstance(h, urllib.request.HTTPSHandler)]
        return h._context

    assert ctx(rt.build_router_opener(True, False)).verify_mode == ssl.CERT_NONE
    assert ctx(rt.build_router_opener(True, True)).verify_mode == ssl.CERT_REQUIRED


# overall deadline


def test_overall_deadline_with_slow_fake():
    release = threading.Event()
    calls = []

    def slow(url, timeout, verify):
        calls.append((url, timeout))
        release.wait(5)
        return FetchResult(200, {}, "")

    start = time.monotonic()
    r = check_router_admin("192.168.1.1", local_network=NET, fetch=slow, timeout=3, budget=0.3)
    elapsed = time.monotonic() - start
    release.set()
    assert elapsed < 1.0
    assert not r.admin_reachable
    assert "time limit" in r.pages[0].error
    assert all("time limit" in p.error for p in r.pages)
    assert len(calls) == 1 and calls[0][1] <= 0.3  # per-request timeout capped by budget


def test_budget_shared_across_ports():
    # Port 80 answers at once; the others hang, so the shared budget runs out.
    # Event-gated (no sleeps racing the budget), so CI load cannot flip the result.
    release = threading.Event()

    def gated(url, timeout, verify):
        if url == "http://192.168.1.1/":
            return FetchResult(200, {}, "<title>ok</title>")
        release.wait(5)
        return FetchResult(200, {}, "")

    try:
        r = check_router_admin("192.168.1.1", local_network=NET, fetch=gated, budget=0.3)
    finally:
        release.set()
    assert r.pages[0].reachable
    assert all(not p.reachable and "time limit" in p.error for p in r.pages[1:])

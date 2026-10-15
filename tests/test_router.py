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

import asyncio
from dataclasses import asdict
import json
import threading
import time

import httpx
import pytest

from crawler.checks import passive_checks
from crawler.engine import Crawler
from crawler.extract import extract
from crawler.models import Config, Extraction, Page, ScanResult
from crawler.report import public_report, render_html, write_reports
from crawler.server import config_from_payload
from crawler.urls import Scope, normalize_url, parameter_names, redact_url


class Body(httpx.AsyncByteStream):
    def __init__(self, text):
        self.data = text.encode() if isinstance(text, str) else text

    async def __aiter__(self):
        for start in range(0, len(self.data), 128):
            yield self.data[start:start + 128]


def response(text="", status=200, headers=None):
    return httpx.Response(status, headers=headers or {"Content-Type": "text/html"}, stream=Body(text))


def run(routes, **kwargs):
    seen = []

    def handler(request):
        seen.append(request)
        route = routes.get(str(request.url))
        return route(request) if callable(route) else response(route) if isinstance(route, str) else response("", 404)

    config = Config("http://test.local/", rate=10000, discover_sitemaps=False, retries=0, **kwargs)
    result = asyncio.run(Crawler(config, transport=httpx.MockTransport(handler)).run())
    return result, seen


def test_url_normalization_preserves_query_semantics():
    assert normalize_url("HTTPS://EXAMPLE.COM:443/a?q=2&q=1#section") == "https://example.com/a?q=2&q=1"
    assert normalize_url("../b", "https://example.com/a/c") == "https://example.com/b"
    assert normalize_url("http://[::1]:8080/") == "http://[::1]:8080/"
    assert normalize_url("https://user:password@example.com/") is None
    assert normalize_url("javascript:alert(1)") is None
    assert normalize_url("http://example.com:bad") is None
    assert normalize_url("http://example.com\\@attacker.test") is None
    assert parameter_names("https://example.com/?id=1&id=2&empty=") == ["empty", "id"]


def test_scope_boundaries_and_explicit_origin():
    scope = Scope("http://example.com/", ["https://api.example.org:8443"], True, ["/logout"])
    assert scope.reason("https://example.com/") is None
    assert scope.reason("http://child.example.com/") is None
    assert scope.reason("http://example.com.attacker.test/") == "out_of_scope"
    assert scope.reason("http://example.com:9000/") == "out_of_scope"
    assert scope.reason("https://api.example.org:8443/") is None
    assert scope.reason("http://example.com/logout") == "excluded"


def test_extract_html_base_forms_and_javascript():
    html = '''<title>A test</title><base href="/app/"><a href="next#x">Next</a>
    <form method="POST" action="save"><input name="password" type="password" value="secret"></form>
    <form><input name="q"></form><img src="photo.png"><script src="/main.js"></script>
    <script>fetch('/api/users'); axios.post('/api/save');</script>'''
    extracted = extract("https://example.com/start", "text/html", html)
    urls = {c.url: c for c in extracted.candidates}
    assert extracted.title == "A test"
    assert urls["https://example.com/app/next"].fetch
    assert not urls["https://example.com/app/photo.png"].fetch
    assert not urls["https://example.com/api/save"].fetch
    assert extracted.forms[0].action == "https://example.com/app/save"
    assert extracted.forms[1].action == "https://example.com/start"
    assert "secret" not in json.dumps(asdict(extracted))


def test_extract_nested_sitemaps_json_and_robots():
    extracted = extract("http://test.local/sitemap.xml", "application/xml", '<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><sitemap><loc>http://test.local/part.xml</loc></sitemap></sitemapindex>')
    assert [c.url for c in extracted.candidates] == ["http://test.local/part.xml"]
    assert not extract("http://test.local/x.xml", "text/xml", '<!DOCTYPE a [<!ENTITY a "boom">]><urlset><loc>&a;</loc></urlset>').candidates
    extracted = extract("http://test.local/api", "application/json", '{"links":{"next":"/api?page=2"}}')
    assert extracted.candidates[0].url == "http://test.local/api?page=2"
    extracted = extract("http://test.local/robots.txt", "text/plain", "Disallow: /private\nSitemap: /map.xml\nDisallow: /*.pdf$")
    assert {c.url for c in extracted.candidates} == {"http://test.local/private", "http://test.local/map.xml"}


def test_passive_findings_and_confidence():
    url = "http://test.local/login"
    body = '<form method="get"><input name="password" type="password"></form><form method="post" action="/save"></form>'
    headers = httpx.Headers({"content-type": "text/html", "set-cookie": "session=private; Path=/", "access-control-allow-origin": "*"})
    findings = passive_checks(url, 200, headers, body, extract(url, "text/html", body))
    rules = {f.rule: f for f in findings}
    assert rules["password-http"].severity == "high"
    assert rules["password-get"].severity == "medium"
    assert rules["csrf-token-not-observed"].confidence == "low"
    assert rules["cors-wildcard"].severity == "info"
    assert "hsts-missing" not in rules
    assert "private" not in json.dumps([asdict(f) for f in findings])


def test_secure_headers_and_nonce_do_not_generate_weak_csp_findings():
    headers = httpx.Headers({"content-type": "text/html", "content-security-policy": "default-src 'self'; script-src 'unsafe-inline' 'nonce-abc'; frame-ancestors 'none'", "strict-transport-security": "max-age=31536000", "referrer-policy": "no-referrer", "x-content-type-options": "nosniff", "set-cookie": "session=secret; Secure; HttpOnly; SameSite=Lax"})
    assert passive_checks("https://test.local/", 200, headers, "", Extraction()) == []


def test_deep_crawl_scope_redirects_dedup_and_forms():
    result, seen = run({
        "http://test.local/": '<a href="/a#one">A</a><a href="/a#two">A</a><a href="/redirect">R</a><a href="http://outside.test/">X</a><form action="/submit" method="post"><input name="a"></form>',
        "http://test.local/a": '<a href="/b">B</a>',
        "http://test.local/b": "<title>Deep page</title>",
        "http://test.local/redirect": lambda _: response(status=302, headers={"Location": "http://outside.test/private"}),
    })
    requested = [str(r.url) for r in seen]
    assert requested.count("http://test.local/a") == 1
    assert "http://test.local/b" in requested
    assert all(url.startswith("http://test.local/") for url in requested)
    assert "http://test.local/submit" not in requested
    assert all(r.method == "GET" for r in seen)
    assert result.stop_reason == "frontier_exhausted"
    assert {i["state"] for i in result.discovered} >= {"fetched", "out_of_scope", "inventory_only"}


def test_credentials_and_cookies_stay_on_exact_origin():
    def root(_):
        return response('<a href="http://other.local/">Other</a><a href="/next">Next</a>', headers={"Content-Type": "text/html", "Set-Cookie": "learned=server-secret; Domain=.local; Path=/"})
    result, seen = run({"http://test.local/": root, "http://test.local/next": "ok", "http://other.local/": "ok"}, allowed_origins=["http://other.local"], headers={"Authorization": "Bearer auth-secret"}, cookies={"session": "cookie-secret"})
    initial = next(r for r in seen if r.url.host == "test.local")
    other = next(r for r in seen if r.url.host == "other.local")
    assert initial.headers["authorization"] == "Bearer auth-secret"
    assert "cookie-secret" in initial.headers["cookie"]
    assert "authorization" not in other.headers
    assert "cookie" not in other.headers
    assert all(r.headers["accept-encoding"] == "identity" for r in seen)
    report = json.dumps(public_report(result))
    assert all(secret not in report for secret in ("auth-secret", "cookie-secret", "server-secret"))


def test_response_limit_and_depth_limit():
    routes = {"http://test.local/": '<a href="/1">1</a><a href="/2">2</a>', "http://test.local/1": '<a href="/deep">Deep</a>'}
    result, seen = run(routes, max_pages=2, concurrency=5)
    assert len(seen) == 2
    assert result.stop_reason == "page_limit"
    assert any(i["state"] == "pending" for i in result.discovered)
    result, seen = run(routes, max_depth=0)
    assert len(seen) == 1
    assert sum(i["state"] == "depth_limit" for i in result.discovered) == 2


def test_query_variants_and_body_limits():
    links = "".join(f'<a href="/search?q={i}">Q</a>' for i in range(10))
    result, seen = run({"http://test.local/": links}, max_variants=2)
    assert len(seen) == 3
    assert sum(i["state"] == "variant_limit" for i in result.discovered) == 8
    result, _ = run({"http://test.local/": "x" * 10000}, max_body_bytes=100)
    assert result.pages[0].size == 100
    assert result.pages[0].truncated
    assert result.pages[0].content_hash is None


def test_duplicate_body_relative_links_are_still_discovered():
    result, seen = run({"http://test.local/": '<a href="/a/">A</a><a href="/b/">B</a>', "http://test.local/a/": '<a href="child">C</a>', "http://test.local/b/": '<a href="child">C</a>'})
    assert {str(r.url) for r in seen} >= {"http://test.local/a/child", "http://test.local/b/child"}
    assert any(p.duplicate_of for p in result.pages)


def test_robots_enforced_before_seed_and_fail_closed():
    routes = {"http://test.local/": '<a href="/private">P</a>', "http://test.local/robots.txt": lambda _: response("User-agent: *\nDisallow: /private", headers={"Content-Type": "text/plain"})}
    result, seen = run(routes, respect_robots=True)
    assert str(seen[0].url).endswith("/robots.txt")
    assert "http://test.local/private" not in [str(r.url) for r in seen]
    assert next(i for i in result.discovered if i["url"].endswith("/private"))["state"] == "robots_blocked"
    result, seen = run({"http://test.local/robots.txt": lambda _: response("", 503)}, respect_robots=True)
    assert len(seen) == 1
    assert result.warnings


def test_redirect_loop_terminates():
    result, seen = run({"http://test.local/": lambda _: response(status=302, headers={"Location": "/next"}), "http://test.local/next": lambda _: response(status=302, headers={"Location": "/"})})
    assert len(seen) == 2
    assert result.stop_reason == "frontier_exhausted"


def test_retry_after_and_cancellation_are_bounded():
    async def scenario():
        stop = threading.Event()
        async def handler(request):
            stop.set()
            return response("", 429, {"Retry-After": "3600"})
        crawler = Crawler(Config("http://test.local/", discover_sitemaps=False, max_duration=5), transport=httpx.MockTransport(handler), stop_event=stop)
        return await asyncio.wait_for(crawler.run(), timeout=1)
    result = asyncio.run(scenario())
    assert result.stop_reason == "cancelled"
    assert any(i["state"] == "pending" for i in result.discovered)


def test_overall_deadline_and_network_error():
    async def slow(request):
        await asyncio.sleep(10)
        return response()
    crawler = Crawler(Config("http://test.local/", max_duration=0.05, discover_sitemaps=False), transport=httpx.MockTransport(slow))
    assert asyncio.run(crawler.run()).stop_reason == "duration_limit"
    def failed(request):
        raise httpx.ConnectError("unreachable", request=request)
    result, _ = run({"http://test.local/": failed})
    assert "ConnectError" in result.pages[0].error


def test_retry_success_clears_previous_response_state():
    calls = []
    def handler(request):
        calls.append(request)
        if len(calls) == 1:
            return response("compressed-body", 503, {"Content-Encoding": "gzip", "Retry-After": "0"})
        return response("<title>Recovered</title>")
    crawler = Crawler(Config("http://test.local/", discover_sitemaps=False, rate=10000), transport=httpx.MockTransport(handler))
    result = asyncio.run(crawler.run())
    assert result.requests == 2
    assert result.pages[0].status == 200
    assert result.pages[0].title == "Recovered"
    assert result.pages[0].error is None
    assert not result.pages[0].truncated


def test_rate_limit_is_shared_across_concurrent_requests():
    starts = []
    def handler(request):
        starts.append(time.monotonic())
        return response('<a href="/a">A</a><a href="/b">B</a>' if request.url.path == "/" else "done")
    crawler = Crawler(Config("http://test.local/", discover_sitemaps=False, rate=20, concurrency=5), transport=httpx.MockTransport(handler))
    asyncio.run(crawler.run())
    assert len(starts) == 3
    assert all(b - a >= 0.04 for a, b in zip(starts, starts[1:]))


def test_report_redaction_and_html_escaping(tmp_path):
    result = ScanResult("https://test.local/?token=private&id=2", pages=[Page("https://test.local/?password=secret", 0, title='<script>alert("XSS")</script>', headers={"set-cookie": "sid=cookie-value", "x-api-key": "key-value"})])
    data = public_report(result)
    encoded = json.dumps(data)
    assert all(secret not in encoded for secret in ["private", "secret", "cookie-value", "key-value"])
    document = render_html(data)
    assert '<script>alert("XSS")</script>' not in document
    assert "&lt;script&gt;" in document
    json_path, html_path = write_reports(result, tmp_path)
    assert json.loads(json_path.read_text())["schema_version"] == 1
    assert html_path.read_text() == document
    assert redact_url("https://test.local/?q=a%20b&token=secret&q=2") == "https://test.local/?q=a%20b&token=REDACTED&q=2"


@pytest.mark.parametrize("payload", [{"url": "http://test.local", "rate": 0}, {"url": "http://test.local", "rate": float("nan")}, {"url": "http://test.local", "max_pages": True}, {"url": "http://test.local", "headers": {"Host": "evil"}}, {"url": "http://test.local", "cookies": {"session": "a\r\nb"}}, {"url": "http://test.local", "unexpected": True}])
def test_bad_config_rejected(payload):
    with pytest.raises(ValueError):
        config_from_payload(payload)

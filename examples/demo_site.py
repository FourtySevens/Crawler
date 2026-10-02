"""Deliberately imperfect local site for demonstrating passive findings."""

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from urllib.parse import urlsplit


def make_demo_server(port: int = 8081) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            path = urlsplit(self.path).path
            status, mime, extra = 200, "text/html; charset=utf-8", {}
            pages = {
                "/": ('Harbor & Pine', '<h1>Harbor &amp; Pine</h1><p>Tools for the everyday explorer.</p><nav><a href="/catalog">Collection</a> <a href="/account">Account</a> <a href="/journal">Journal</a> <a href="/legacy">Help</a></nav><script src="/assets/app.js"></script><a href="https://outside.example/">Partner site</a>'),
                "/catalog": ('Our collection', '<h1>The collection</h1><a href="/catalog/trail-pack">Trail pack</a><a href="/catalog/weekender">Weekender</a><a href="/catalog?q=canvas">Canvas collection</a><a href="/api/products">Product API</a><form action="/catalog" method="GET"><input name="q" type="search"><button>Search</button></form>'),
                "/catalog/trail-pack": ('Trail pack', '<h1>Trail pack</h1><img src="/assets/pack.png"><a href="/catalog/weekender">Compare with weekender</a>'),
                "/catalog/weekender": ('Weekender', '<h1>Weekender</h1><a href="/catalog/trail-pack">Compare with trail pack</a>'),
                "/account": ('Your account', '<h1>Sign in</h1><form action="/session" method="POST"><input name="email" type="email"><input name="password" type="password"><button>Continue</button></form>'),
                "/journal": ('Field notes', '<h1>Field notes</h1><a href="/journal/choosing-a-pack">Choosing a pack</a><a href="/missing">An old article</a>'),
                "/journal/choosing-a-pack": ('Choosing a pack', '<h1>Choosing a pack</h1><a href="/catalog/trail-pack">Explore our trail pack</a>'),
                "/help": ('How can we help?', '<h1>How can we help?</h1><form action="/contact" method="POST"><input name="email"><textarea name="message"></textarea><button>Send</button></form><a href="mailto:hello@example.test">Email us</a>'),
                "/internal/status": ('Service status', '<h1>Service status</h1><a href="/diagnostics">Diagnostics</a>'),
                "/archive/": ('Index of /archive/', '<h1>Index of /archive/</h1><a href="/archive/catalog.pdf">catalog.pdf</a>'),
            }
            if path in pages:
                title, content = pages[path]
                body = f'<!doctype html><html lang="en"><head><title>{title}</title><meta name="description" content="Local demo storefront"><link rel="stylesheet" href="/assets/site.css"></head><body>{content}<footer><a href="/">Home</a></footer></body></html>'
                if path == "/account":
                    extra["Set-Cookie"] = "demo_session=demo-value; Path=/"
            elif path == "/robots.txt":
                mime, body = "text/plain", "User-agent: *\nDisallow: /internal/\nSitemap: /sitemap.xml\n"
            elif path == "/sitemap.xml":
                mime, body = "application/xml", '<sitemapindex><sitemap><loc>/sitemaps/pages.xml</loc></sitemap></sitemapindex>'
            elif path == "/sitemaps/pages.xml":
                mime, body = "application/xml", '<urlset><url><loc>/internal/status</loc></url><url><loc>/archive/</loc></url></urlset>'
            elif path == "/assets/app.js":
                mime, body = "application/javascript", "fetch('/api/products'); const next = '/api/inventory';"
            elif path == "/assets/site.css":
                mime, body = "text/css", "body{font:18px system-ui;max-width:900px;margin:60px auto;padding:20px}a{display:inline-block;margin:12px;color:#246c60}"
            elif path == "/api/products":
                mime, body = "application/json", json.dumps({"products": [{"name": "Trail pack"}], "next": "/api/products?page=2"})
                extra["Access-Control-Allow-Origin"] = "*"
            elif path == "/legacy":
                status, body = 302, ""
                extra["Location"] = "/help"
            elif path == "/diagnostics":
                status, body = 500, "<h1>Application error</h1><pre>Traceback (most recent call last):\n  Example demonstration error</pre>"
            else:
                status, body = 404, "<h1>Page not found</h1>"
            content = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(content)))
            for key, value in extra.items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(content)

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8081)
    args = parser.parse_args()
    server = make_demo_server(args.port)
    print(f"Demo site: http://127.0.0.1:{server.server_address[1]}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

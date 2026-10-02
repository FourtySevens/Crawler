# Scope Crawler

A website crawler and passive security assessment dashboard for penetration testing. Map reachable pages, inspect forms and parameters, and review security findings with evidence and remediation. Run assessments in the browser or automate them from the command line.

## Start the dashboard

Requires Python 3.11 or newer.

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
python -m crawler serve
```

Open **http://127.0.0.1:8765**, enter your target URL, and select **Start crawl**. The server binds to loopback. Scan settings include response and depth limits, request rate, concurrency, time budgets, excluded URL patterns, extra origins, session headers/cookies, and an HTTP proxy.

The dependencies are already available in this development workspace, so `python3 -m crawler serve` also runs directly without installation. The installed command is `scope-crawler`.

### Try the local demo

```sh
python -m examples.run_demo
```

This starts the dashboard on port **8765** and a deliberately imperfect demo storefront on **8081**. Crawl `http://127.0.0.1:8081` to see nested sitemap discovery, redirects, an API, forms, a directory listing, error disclosures, and cookie/header findings. The demo exposes only localhost. If the dashboard is already running, use `python -m examples.demo_site` to start just the target.

## Included functionality

| Area | Capabilities |
| --- | --- |
| Discovery | HTML links, frames, meta refresh, redirects, scripts, stylesheets, CSS resource URLs, robots paths, sitemap indexes and nested sitemaps, JSON navigation links |
| Endpoint inventory | JavaScript literal API references, form actions, external links, binary assets, query parameter names, discovery source and link graph |
| Response inventory | Status, title, description, content type, response headers, elapsed time, captured size, body hash, duplicate content, redirect target, depth, truncation and errors |
| Forms | Method, action, encoding, field names and types; field values omitted |
| Passive findings | CSP, framing protection, MIME sniffing, HSTS, referrer policy, cookie attributes, HTTP password forms, GET password forms, mixed resources, external script integrity, technology disclosure, CORS configuration, error signatures, directory listings, possible CSRF coverage gaps |
| Sessions | Custom request headers and cookies; server cookie updates; credentials isolated to each exact origin |
| Crawl controls | Concurrent requests, global request-start rate, total duration, per-request wall-clock timeout, retries, response size limit, depth/response/discovery/query-variant limits, optional robots enforcement |
| Dashboard | Live counts and recent responses, scan history for the running server session, URL search/state filtering/pagination, severity filtering, grouped findings, forms, stop control |
| Reports | Self-contained searchable HTML, structured JSON, coverage states, rule IDs, evidence, confidence, remediation references |

The implementation uses [HTTPX asynchronous streaming](https://www.python-httpx.org/async/) and Beautiful Soup. The assessment structure follows ZAP's spider/passive-scan workflow; [ZAP's feature list](https://www.zaproxy.org/docs/desktop/start/features/) also includes capabilities outside this project's current scope. Header checks reference [OWASP's HTTP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html).

## Scope and coverage

The default scope is the exact target origin: scheme, hostname, and port. A normal port-80 HTTP seed may upgrade to HTTPS on port 443. Every discovered URL and redirect is checked before requesting it. Additional origins are explicit; subdomain discovery is optional and follows the seed scheme/port. Excluded URLs remain visible in the inventory.

Requests use **GET**. Forms are inventoried without submission. JavaScript API guesses are recorded without requesting them because the expected method and inputs are unknown; an endpoint directly linked by HTML or JSON may still be fetched. Session cookies and custom headers are sent only to the exact seed origin; separately allowed origins get separate cookie jars and no supplied credentials. For authenticated crawling after an HTTP-to-HTTPS redirect, start with the HTTPS URL.

By default, robots.txt is used for discovery, and its restrictions are **not enforced**. Enable **Respect robots.txt** to enforce them. In that mode a missing robots file (404/410) allows crawling, while an inaccessible, redirected, truncated, or invalidly retrieved file blocks its origin. Robots crawl-delay directives are not applied; configure the request rate explicitly.

Defaults: 1,000 requested URLs, depth 12, five concurrent requests, five request starts/second, 15-second request timeout, 15-minute total budget, 2 MB per body, 20 query variants per path, and 20,000 discovered URLs. Robots fetches count toward the response limit; retries increase the HTTP request count. Sitemap entries and redirects do not increase depth. Stop cancels in-flight requests and retains completed observations.

No crawler can guarantee every page: unlinked routes, login workflows, application state, generated URL spaces, and configured limits all affect coverage. This version does not execute JavaScript, click controls, complete interactive logins, submit forms, intercept browser traffic, or launch active vulnerability payloads. Supply session credentials or explicit additional starting paths in separate scans for authenticated/static exploration. JavaScript-only applications require a future browser-rendering component. The crawler does not currently import OpenAPI definitions, decompress `.gz` sitemaps, or inspect downloaded binary documents.

HTTP requests ask for uncompressed responses so the body limit also controls buffering. Servers that return compression regardless are recorded with a skipped-body error. Duplicate body hashes are annotated, while links are still extracted because relative URLs can differ across pages.

## Command line

```sh
python -m crawler crawl https://app.example.com \
  --max-pages 5000 --max-depth 20 --rate 4 --concurrency 4 \
  --exclude '/logout' --exclude '/delete' \
  --allow-origin https://api.example.com \
  --output reports/assessment
```

```sh
python -m crawler crawl https://app.example.com \
  --auth-file auth.json --respect-robots --fail-on high
```

An `auth.json` file uses this shape:

```json
{
  "headers": {"Authorization": "Bearer YOUR_TOKEN"},
  "cookies": {"session": "YOUR_SESSION_COOKIE"}
}
```

Run `python -m crawler crawl --help` for all options. Exit codes: `0` completed, `1` invalid configuration or no HTTP responses, `2` finding severity threshold met, `130` cancelled. Always inspect `stop_reason` and coverage for limits; reaching a crawl limit is not a process error.

### Use with ZAP

Send crawler requests through a running ZAP proxy:

```sh
python -m crawler crawl http://127.0.0.1:8081 \
  --proxy http://127.0.0.1:8080
```

HTTPS interception requires trusting the proxy's certificate. This version offers `--insecure` (or disabling **Verify TLS certificates** in the dashboard) for explicit local testing; reports record that choice. Proxy environment variables are not used automatically.

## Reports and interpretation

Dashboard reports are written to `reports/<scan-id>/report.html` and `report.json`. CLI reports use the specified output directory; reusing it replaces that directory's prior `report.html` and `report.json`. Dashboard history holds the last 20 scans from the current server session. Files remain on disk after restart, but history is not reloaded automatically.

JSON contains `summary`, `settings`, `pages`, `findings`, `discovered`, `edges`, `warnings`, timestamps, and `stop_reason`. Discovery states distinguish fetched, error, out of scope, excluded, robots blocked, inventory only, depth limited, query-variant limited, and pending URLs. A `frontier_exhausted` result means the crawl queue is exhausted; inventory-only and limited URLs may still exist.

Severity describes potential impact. Confidence describes how directly a response supports the finding. Observing a missing CSRF field or a wildcard CORS header does not prove an exploitable vulnerability; these are informational review hints. Cookie HttpOnly checks also need context because some cookies intentionally support JavaScript.

Reports omit response bodies, form values, supplied authentication configuration, and cookie/header credential values. Query values with recognized sensitive names (such as `token`, `password`, `session`, and `api_key`) are masked. This is targeted redaction: sensitive data in paths, ordinary parameters, titles, or other unexpected locations can still appear. Treat reports as assessment data. Target-provided text is escaped in the dashboard and HTML report.

## Development and verification

```sh
python -m pytest -q
node --check crawler/static/app.js
```

Tests exercise URL normalization, scope and redirect boundaries, credential isolation, extraction, passive findings, budgets, robots behavior, cancellation, report redaction/escaping, dashboard request validation, and a full dashboard-to-demo HTTP crawl. HTTP integration tests bind ephemeral loopback ports.

Code layout: `crawler/engine.py` coordinates discovery and requests; `extract.py` parses content; `checks.py` defines passive rules; `report.py` prepares exports; `server.py` serves the local API/dashboard; `static/` contains the browser interface.

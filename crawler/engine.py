from __future__ import annotations

import asyncio
from collections import Counter, deque
from contextlib import AsyncExitStack
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import hashlib
import math
import threading
import time
from typing import Callable
from urllib.parse import urlsplit
from urllib.robotparser import RobotFileParser

import httpx

from .checks import passive_checks
from .extract import extract
from .models import Candidate, Config, Page, ScanResult, utc_now
from .urls import Scope, is_binary, normalize_url, origin, parameter_names


class BudgetReached(Exception):
    pass


class RateLimiter:
    def __init__(self, rate: float):
        self.interval = 1 / rate
        self.next_request = 0.0
        self.lock = asyncio.Lock()

    async def wait(self) -> None:
        async with self.lock:
            await asyncio.sleep(max(0, self.next_request - time.monotonic()))
            self.next_request = time.monotonic() + self.interval


class Crawler:
    def __init__(self, config: Config, *, transport: httpx.AsyncBaseTransport | None = None,
                 on_progress: Callable[[ScanResult], None] | None = None,
                 stop_event: threading.Event | None = None):
        self.config = config
        seed = normalize_url(config.url)
        if seed is None:
            raise ValueError("Target must be an HTTP or HTTPS URL without embedded credentials")
        self.scope = Scope(seed, config.allowed_origins, config.include_subdomains, config.excludes)
        self.result = ScanResult(seed, settings={
            "max_pages": config.max_pages, "max_depth": config.max_depth,
            "concurrency": config.concurrency, "requests_per_second": config.rate,
            "max_duration_seconds": config.max_duration, "max_body_bytes": config.max_body_bytes,
            "max_discovered": config.max_discovered, "max_variants_per_path": config.max_variants,
            "respect_robots": config.respect_robots, "verify_tls": config.verify_tls,
            "include_subdomains": config.include_subdomains, "allowed_origins": sorted(self.scope.origins),
            "exclude_patterns": config.excludes, "authenticated": bool(config.headers or config.cookies),
        })
        self.transport = transport
        self.on_progress = on_progress
        self.stop_event = stop_event or threading.Event()
        self.frontier: deque[tuple[str, int, str | None]] = deque()
        self.inventory: dict[str, dict] = {}
        self.edge_keys: set[tuple[str, str, str]] = set()
        self.variants: Counter = Counter()
        self.hashes: dict[str, str] = {}
        self.clients: dict[str, httpx.AsyncClient] = {}
        self.clients_lock = asyncio.Lock()
        self.robots: dict[str, RobotFileParser] = {}
        self.robots_locks: dict[str, asyncio.Lock] = {}
        self.rate = RateLimiter(config.rate)
        self.attempts = 0
        self.stack = AsyncExitStack()

    def _warn(self, message: str) -> None:
        if message not in self.result.warnings:
            self.result.warnings.append(message)

    def _discover(self, candidate: Candidate, depth: int, source: str | None) -> None:
        url = candidate.url
        if source and len(self.edge_keys) < self.config.max_discovered * 5:
            key = (source, url, candidate.kind)
            if key not in self.edge_keys:
                self.edge_keys.add(key)
                self.result.edges.append({"source": source, "target": url, "kind": candidate.kind})
        existing = self.inventory.get(url)
        if existing:
            # An endpoint guessed from JS can later become an actual linked page.
            if existing["state"] == "inventory_only" and candidate.fetch:
                existing["state"] = "queued"
            elif existing["state"] == "depth_limit" and depth <= self.config.max_depth:
                existing["state"] = "queued"
            else:
                return
        elif len(self.inventory) >= self.config.max_discovered:
            self._warn("Discovery limit reached; additional URLs and edges may be omitted.")
            return
        else:
            existing = {"url": url, "kind": candidate.kind, "source": source, "depth": depth, "state": "queued"}
            self.inventory[url] = existing
            self.result.discovered.append(existing)
        existing.update(depth=depth, source=source, kind=candidate.kind)
        reason = self.scope.reason(url)
        if reason:
            existing["state"] = reason
        elif is_binary(url) or not candidate.fetch:
            existing["state"] = "inventory_only"
        elif depth > self.config.max_depth:
            existing["state"] = "depth_limit"
        else:
            p = urlsplit(url)
            path_key = (origin(url), p.path)
            if p.query and self.variants[path_key] >= self.config.max_variants:
                existing["state"] = "variant_limit"
            else:
                if p.query:
                    self.variants[path_key] += 1
                self.frontier.append((url, depth, source))

    async def _client(self, url: str) -> httpx.AsyncClient:
        key = origin(url)
        async with self.clients_lock:
            if key not in self.clients:
                headers = {"User-Agent": self.config.user_agent, "Accept-Encoding": "identity"}
                cookies = None
                if key == origin(self.result.target):
                    headers.update(self.config.headers)
                    cookies = self.config.cookies
                # Separate cookie jars ensure credentials learned on one origin cannot
                # silently cross to a different origin, port, or scheme.
                client = httpx.AsyncClient(
                    headers=headers, cookies=cookies, timeout=self.config.timeout,
                    verify=self.config.verify_tls, proxy=self.config.proxy,
                    follow_redirects=False, trust_env=False, transport=self.transport,
                    limits=httpx.Limits(max_connections=self.config.concurrency, max_keepalive_connections=self.config.concurrency),
                )
                self.clients[key] = await self.stack.enter_async_context(client)
        return self.clients[key]

    async def _fetch(self, url: str, depth: int, source: str | None) -> tuple[Page, str, httpx.Headers]:
        if self.stop_event.is_set() or self.attempts >= self.config.max_pages:
            raise BudgetReached()
        self.attempts += 1
        page = Page(url, depth, source, parameters=parameter_names(url))
        started = time.monotonic()
        for attempt in range(self.config.retries + 1):
            if self.stop_event.is_set():
                raise BudgetReached()
            await self.rate.wait()
            self.result.requests += 1
            client = await self._client(url)
            try:
                page.status = None
                page.headers = {}
                page.truncated = False
                page.error = None
                # Wall-clock timeout also bounds servers that slowly drip bytes.
                async with asyncio.timeout(self.config.timeout):
                    async with client.stream("GET", url) as response:
                        headers = response.headers
                        page.status = response.status_code
                        page.headers = dict(headers)
                        page.content_type = headers.get("content-type", "")
                        chunks = bytearray()
                        # Identity encoding avoids decompressing attacker-controlled
                        # compressed bodies beyond the configured memory budget.
                        if headers.get("content-encoding", "identity").lower() not in {"", "identity"}:
                            page.truncated = True
                            page.error = "Server returned compressed content despite Accept-Encoding: identity; body skipped"
                        else:
                            async for chunk in response.aiter_raw(chunk_size=65536):
                                remaining = self.config.max_body_bytes - len(chunks)
                                chunks.extend(chunk[:remaining])
                                if len(chunk) > remaining:
                                    page.truncated = True
                                    break
                        page.size = len(chunks)
                        body = bytes(chunks).decode(response.encoding or "utf-8", errors="replace")
                        if page.status in {429, 502, 503, 504} and attempt < self.config.retries:
                            retry_after = headers.get("retry-after", "")
                            try:
                                delay = max(0.0, float(retry_after))
                                if not math.isfinite(delay):
                                    delay = 0.5 * 2 ** attempt
                            except ValueError:
                                try:
                                    delay = max(0.0, (parsedate_to_datetime(retry_after) - datetime.now(timezone.utc)).total_seconds())
                                except (ValueError, TypeError, OverflowError):
                                    delay = 0.5 * 2 ** attempt
                        else:
                            page.elapsed_ms = round((time.monotonic() - started) * 1000, 1)
                            if chunks and not page.truncated:
                                page.content_hash = hashlib.sha256(chunks).hexdigest()
                            return page, body, headers
                await asyncio.sleep(delay)
            except (httpx.HTTPError, TimeoutError, LookupError) as exc:
                if attempt < self.config.retries:
                    await asyncio.sleep(0.5 * 2 ** attempt)
                else:
                    page.error = f"{type(exc).__name__}: {exc}"
        page.elapsed_ms = round((time.monotonic() - started) * 1000, 1)
        return page, "", httpx.Headers(page.headers)

    def _record(self, page: Page, body: str, headers: httpx.Headers) -> None:
        self.result.pages.append(page)
        item = self.inventory.get(page.url)
        if item:
            item["state"] = "error" if page.error else "fetched"
        if page.error:
            return
        if page.status and 300 <= page.status < 400 and headers.get("location"):
            page.redirect_to = normalize_url(headers["location"], page.url)
            if page.redirect_to:
                self._discover(Candidate(page.redirect_to, "redirect"), page.depth, page.url)
        if not page.status:
            return
        extracted = extract(page.url, page.content_type, body)
        page.title, page.description = extracted.title, extracted.description
        page.forms, page.emails = extracted.forms, extracted.emails
        page.technologies = extracted.technologies + [f"{key}: {headers[key]}" for key in ("server", "x-powered-by") if key in headers]
        self.result.findings.extend(passive_checks(page.url, page.status, headers, body, extracted))
        if page.content_hash:
            page.duplicate_of = self.hashes.get(page.content_hash)
            self.hashes.setdefault(page.content_hash, page.url)
        # Parse duplicate bodies too: relative links can resolve differently.
        for candidate in extracted.candidates:
            if not self.config.discover_sitemaps and candidate.kind == "sitemap":
                candidate.fetch = False
            next_depth = page.depth if candidate.kind in {"sitemap", "robots_path"} else page.depth + 1
            self._discover(candidate, next_depth, page.url)

    async def _ensure_robots(self, url: str) -> RobotFileParser:
        key = origin(url)
        lock = self.robots_locks.setdefault(key, asyncio.Lock())
        async with lock:
            if key in self.robots:
                return self.robots[key]
            robots_url = key + "/robots.txt"
            parser = RobotFileParser(robots_url)
            if self.scope.reason(robots_url):
                parser.disallow_all = True
                self._warn(f"robots.txt is excluded for {key}; robots mode blocks this origin.")
            else:
                self._discover(Candidate(robots_url, "robots"), 0, None)
                page, body, headers = await self._fetch(robots_url, 0, None)
                self._record(page, body, headers)
                if page.status in {404, 410}:
                    parser.allow_all = True
                elif page.error or page.truncated or not page.status or not 200 <= page.status < 300:
                    parser.disallow_all = True
                    self._warn(f"Could not load a complete robots.txt for {key}; robots mode blocks this origin.")
                else:
                    parser.parse(body.splitlines())
            self.robots[key] = parser
            return parser

    async def _visit(self, url: str, depth: int, source: str | None) -> None:
        try:
            if self.config.respect_robots:
                parser = await self._ensure_robots(url)
                if self.inventory[url]["state"] in {"fetched", "error"}:
                    return
                if not parser.can_fetch(self.config.user_agent, url):
                    self.inventory[url]["state"] = "robots_blocked"
                    return
            page, body, headers = await self._fetch(url, depth, source)
            self._record(page, body, headers)
        except BudgetReached:
            self.inventory[url]["state"] = "pending"

    async def _crawl(self) -> None:
        if self.config.respect_robots:
            try:
                await self._ensure_robots(self.result.target)
            except BudgetReached:
                return
        while self.frontier and not self.stop_event.is_set() and self.attempts < self.config.max_pages:
            batch = []
            while self.frontier and len(batch) < self.config.concurrency:
                url, depth, source = self.frontier.popleft()
                if self.inventory[url]["state"] == "queued":
                    self.inventory[url]["state"] = "fetching"
                    batch.append(self._visit(url, depth, source))
            if batch:
                await asyncio.gather(*batch)
                if self.on_progress:
                    self.on_progress(self.result)

    async def _until_stopped(self) -> None:
        async def watch_stop() -> None:
            while not self.stop_event.is_set():
                await asyncio.sleep(0.1)

        crawl = asyncio.create_task(self._crawl())
        stopper = asyncio.create_task(watch_stop())
        try:
            done, _ = await asyncio.wait({crawl, stopper}, return_when=asyncio.FIRST_COMPLETED)
            if crawl in done:
                await crawl
        finally:
            crawl.cancel()
            stopper.cancel()
            await asyncio.gather(crawl, stopper, return_exceptions=True)

    async def run(self) -> ScanResult:
        # Always request identity, including when the caller supplied custom headers.
        self.config.headers = {k: v for k, v in self.config.headers.items() if k.lower() != "accept-encoding"}
        self.config.headers["Accept-Encoding"] = "identity"
        self._discover(Candidate(self.result.target, "seed"), 0, None)
        if self.config.discover_sitemaps:
            self._discover(Candidate(origin(self.result.target) + "/robots.txt", "robots"), 0, None)
            self._discover(Candidate(origin(self.result.target) + "/sitemap.xml", "sitemap"), 0, None)
        if not self.config.verify_tls:
            self._warn("TLS certificate verification was disabled for this scan.")
        try:
            async with self.stack:
                async with asyncio.timeout(self.config.max_duration):
                    await self._until_stopped()
            self.result.stop_reason = "cancelled" if self.stop_event.is_set() else "page_limit" if self.attempts >= self.config.max_pages and any(i["state"] in {"queued", "pending"} for i in self.inventory.values()) else "frontier_exhausted"
        except TimeoutError:
            self.result.stop_reason = "duration_limit"
        except asyncio.CancelledError:
            self.result.stop_reason = "cancelled"
        finally:
            for item in self.inventory.values():
                if item["state"] in {"queued", "fetching"}:
                    item["state"] = "pending"
            self.result.finished_at = utc_now()
            if self.on_progress:
                self.on_progress(self.result)
        return self.result

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
import re
import sys
import threading
import signal

from . import __version__
from .engine import Crawler
from .models import Config
from .report import summary, write_reports
from .server import config_from_payload, serve


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description="Scope Crawler — website discovery and passive security assessment")
    root.add_argument("--version", action="version", version=__version__)
    commands = root.add_subparsers(dest="command")
    dashboard = commands.add_parser("serve", help="Start the local web dashboard (default)")
    dashboard.add_argument("--port", type=int, default=8765)
    dashboard.add_argument("--output", type=Path, default=Path("reports"))
    crawl = commands.add_parser("crawl", help="Run a crawl and write HTML/JSON reports")
    crawl.add_argument("url", help="HTTP(S) target URL")
    crawl.add_argument("--output", type=Path, default=Path("reports/latest"))
    crawl.add_argument("--max-pages", type=int, default=1000)
    crawl.add_argument("--max-depth", type=int, default=12)
    crawl.add_argument("--concurrency", type=int, default=5)
    crawl.add_argument("--rate", type=float, default=5, help="Maximum request starts per second, across the whole crawl")
    crawl.add_argument("--timeout", type=float, default=15)
    crawl.add_argument("--max-duration", type=float, default=900, help="Total time budget in seconds")
    crawl.add_argument("--include-subdomains", action="store_true")
    crawl.add_argument("--allow-origin", action="append", default=[], help="Additional exact origin, including port (repeatable)")
    crawl.add_argument("--exclude", action="append", default=[], help="Exclude URLs matching a regex (repeatable)")
    crawl.add_argument("--respect-robots", action="store_true")
    crawl.add_argument("--no-sitemaps", action="store_true")
    crawl.add_argument("--insecure", action="store_true", help="Disable TLS certificate validation")
    crawl.add_argument("--proxy", help="Forward requests through an HTTP(S) proxy, such as ZAP")
    crawl.add_argument("--auth-file", type=Path, help='JSON object with "headers" and/or "cookies"; sent only to the seed origin')
    crawl.add_argument("--fail-on", choices=["high", "medium", "low", "info"], help="Exit 2 when findings meet this severity or higher")
    return root


def main(argv: list[str] | None = None) -> int:
    root = parser()
    args = root.parse_args(argv)
    if args.command in {None, "serve"}:
        try:
            serve(getattr(args, "port", 8765), getattr(args, "output", Path("reports")))
        except (OSError, ValueError) as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1
        return 0
    try:
        auth = json.loads(args.auth_file.read_text()) if args.auth_file else {}
        if not isinstance(auth, dict) or set(auth) - {"headers", "cookies"}:
            raise ValueError("Auth file must contain only headers and/or cookies objects")
        config = config_from_payload({
            "url": args.url, "max_pages": args.max_pages, "max_depth": args.max_depth,
            "concurrency": args.concurrency, "rate": args.rate, "timeout": args.timeout,
            "max_duration": args.max_duration, "include_subdomains": args.include_subdomains,
            "allowed_origins": args.allow_origin, "excludes": args.exclude,
            "respect_robots": args.respect_robots, "discover_sitemaps": not args.no_sitemaps,
            "verify_tls": not args.insecure, "proxy": args.proxy, **auth,
        })
        stop = threading.Event()
        previous_handler = signal.signal(signal.SIGINT, lambda *_: stop.set())

        def progress(result):
            print(f"\rResponses: {len(result.pages)} · Discovered: {len(result.discovered)} · Findings: {len(result.findings)}", end="", file=sys.stderr, flush=True)

        try:
            result = asyncio.run(Crawler(config, stop_event=stop, on_progress=progress).run())
        finally:
            signal.signal(signal.SIGINT, previous_handler)
        json_path, html_path = write_reports(result, args.output)
        print(file=sys.stderr)
        print(json.dumps({"stop_reason": result.stop_reason, **summary(result), "json_report": str(json_path.resolve()), "html_report": str(html_path.resolve())}, indent=2))
        if result.stop_reason == "cancelled":
            return 130
        if not any(page.status is not None for page in result.pages):
            return 1
        if args.fail_on:
            levels = ["high", "medium", "low", "info"]
            if any(levels.index(f.severity) <= levels.index(args.fail_on) for f in result.findings):
                return 2
        return 0
    except (OSError, ValueError, TypeError, re.error) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

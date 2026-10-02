from __future__ import annotations

import asyncio
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import secrets
import threading
from urllib.parse import urlsplit

from .engine import Crawler
from .models import Config, ScanResult, utc_now
from .report import sanitize, summary, write_reports


STATIC = Path(__file__).with_name("static")


def config_from_payload(payload: dict) -> Config:
    if not isinstance(payload, dict):
        raise ValueError("Expected a JSON object")
    allowed = {"url", "max_pages", "max_depth", "concurrency", "rate", "timeout", "max_duration", "include_subdomains", "allowed_origins", "excludes", "respect_robots", "discover_sitemaps", "verify_tls", "headers", "cookies", "proxy"}
    unknown = set(payload) - allowed
    if unknown:
        raise ValueError("Unknown setting: " + ", ".join(sorted(unknown)))
    if not isinstance(payload.get("url"), str) or len(payload["url"]) > 8192:
        raise ValueError("Enter a valid target URL")
    for key, maximum in {"max_pages": 100_000, "max_depth": 100, "concurrency": 50}.items():
        if key in payload and (type(payload[key]) is not int or payload[key] > maximum):
            raise ValueError(f"{key} must be an integer no greater than {maximum}")
    for key in ("rate", "timeout", "max_duration"):
        if key in payload and type(payload[key]) not in {int, float}:
            raise ValueError(f"{key} must be a number")
    for key in ("include_subdomains", "respect_robots", "discover_sitemaps", "verify_tls"):
        if key in payload and type(payload[key]) is not bool:
            raise ValueError(f"{key} must be true or false")
    for key in ("allowed_origins", "excludes"):
        if key in payload and (not isinstance(payload[key], list) or len(payload[key]) > 50 or any(not isinstance(v, str) or len(v) > 500 for v in payload[key])):
            raise ValueError(f"{key} must be an array of at most 50 short strings")
    for key in ("headers", "cookies"):
        mapping = payload.get(key, {})
        if not isinstance(mapping, dict) or len(mapping) > 100 or any(not isinstance(v, str) or "\r" in v or "\n" in v or not isinstance(k, str) or not re.fullmatch(r"[!#$%&'*+.^_`|~\w-]+", k, flags=re.ASCII) for k, v in mapping.items()):
            raise ValueError(f"{key} must be an object of valid names and string values")
    if any(k.lower() in {"host", "content-length", "transfer-encoding", "connection"} for k in payload.get("headers", {})):
        raise ValueError("Host, connection, and body framing headers are managed by the crawler")
    proxy = payload.get("proxy")
    if proxy is not None and (not isinstance(proxy, str) or not proxy.startswith(("http://", "https://"))):
        raise ValueError("Proxy must be an HTTP or HTTPS URL")
    return Config(**payload)


class ScanManager:
    def __init__(self, output: Path):
        self.output = output
        self.jobs: dict[str, dict] = {}
        self.stops: dict[str, threading.Event] = {}
        self.lock = threading.Lock()

    def start(self, config: Config) -> str:
        # Validate URL and regex scope before accepting a background job.
        crawler = Crawler(config)
        with self.lock:
            if any(job["status"] in {"running", "stopping"} for job in self.jobs.values()):
                raise RuntimeError("A scan is already running. Stop it before starting another.")
            if len(self.jobs) >= 20:
                oldest = next(iter(self.jobs))
                self.jobs.pop(oldest)
                self.stops.pop(oldest, None)
            scan_id = secrets.token_hex(8)
            stop = threading.Event()
            self.stops[scan_id] = stop
            self.jobs[scan_id] = {"id": scan_id, "target": sanitize(crawler.result.target), "status": "running", "started_at": utc_now(), "finished_at": None, "stop_reason": "running", "summary": summary(crawler.result), "pages": [], "findings": [], "warnings": [], "error": None}

        def progress(result: ScanResult) -> None:
            with self.lock:
                self.jobs[scan_id].update({
                    "summary": summary(result), "stop_reason": result.stop_reason,
                    "pages": sanitize([asdict(page) for page in result.pages[-50:]]),
                    "findings": sanitize([asdict(finding) for finding in result.findings[-100:]]),
                    "warnings": sanitize(result.warnings),
                })

        def worker() -> None:
            crawler.on_progress = progress
            crawler.stop_event = stop
            try:
                result = asyncio.run(crawler.run())
                write_reports(result, self.output / scan_id)
                with self.lock:
                    self.jobs[scan_id].update(status="cancelled" if result.stop_reason == "cancelled" else "complete", finished_at=result.finished_at)
            except Exception as exc:
                with self.lock:
                    self.jobs[scan_id].update(status="failed", error=sanitize(f"{type(exc).__name__}: {exc}"), finished_at=utc_now())

        threading.Thread(target=worker, name=f"scan-{scan_id}", daemon=True).start()
        return scan_id

    def snapshot(self, scan_id: str | None = None):
        with self.lock:
            value = self.jobs.get(scan_id) if scan_id else list(reversed(self.jobs.values()))
            # Detach mutable state before the HTTP thread serializes it.
            return json.loads(json.dumps(value))

    def stop(self, scan_id: str) -> bool:
        with self.lock:
            if scan_id not in self.jobs:
                return False
            if self.jobs[scan_id]["status"] == "running":
                self.jobs[scan_id]["status"] = "stopping"
                self.stops[scan_id].set()
            return True


def make_server(host: str, port: int, output: Path) -> ThreadingHTTPServer:
    manager = ScanManager(output)
    token = secrets.token_urlsafe(32)

    class Handler(BaseHTTPRequestHandler):
        server_version = "ScopeCrawler"

        def log_message(self, format: str, *args) -> None:
            pass

        def send(self, status: int, content: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            if not self.path.startswith("/reports/"):
                self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
            self.end_headers()
            try:
                self.wfile.write(content)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def json_response(self, status: int, payload) -> None:
            self.send(status, json.dumps(payload, ensure_ascii=False).encode(), "application/json; charset=utf-8")

        def same_origin(self) -> bool:
            actual_port = self.server.server_address[1]
            allowed_hosts = {f"localhost:{actual_port}", f"127.0.0.1:{actual_port}"}
            request_host = self.headers.get("Host", "")
            if request_host not in allowed_hosts:
                self.json_response(403, {"error": "Unrecognized dashboard host"})
                return False
            request_origin = self.headers.get("Origin")
            if request_origin and request_origin != "http://" + request_host:
                self.json_response(403, {"error": "Cross-origin requests are not permitted"})
                return False
            if self.headers.get("Sec-Fetch-Site") == "cross-site" and not (self.command == "GET" and self.path == "/" and self.headers.get("Sec-Fetch-Mode") == "navigate"):
                self.json_response(403, {"error": "Cross-site requests are not permitted"})
                return False
            return True

        def do_GET(self) -> None:
            if not self.same_origin():
                return
            path = urlsplit(self.path).path
            if path == "/api/session":
                self.json_response(200, {"token": token})
            elif path == "/api/scans":
                self.json_response(200, manager.snapshot())
            elif re.fullmatch(r"/api/scans/[a-f0-9]{16}", path):
                job = manager.snapshot(path.rsplit("/", 1)[1])
                self.json_response(200 if job else 404, job or {"error": "Scan not found"})
            elif re.fullmatch(r"/reports/[a-f0-9]{16}/report\.(json|html)", path):
                file = output / path.split("/")[2] / path.split("/")[3]
                if file.is_file():
                    self.send(200, file.read_bytes(), "application/json; charset=utf-8" if file.suffix == ".json" else "text/html; charset=utf-8")
                else:
                    self.json_response(404, {"error": "Report not ready"})
            elif path in {"/", "/app.js", "/style.css"}:
                name, mime = {"/": ("index.html", "text/html"), "/app.js": ("app.js", "text/javascript"), "/style.css": ("style.css", "text/css")}[path]
                self.send(200, (STATIC / name).read_bytes(), mime + "; charset=utf-8")
            elif path == "/favicon.ico":
                self.send(204, b"", "image/x-icon")
            else:
                self.json_response(404, {"error": "Not found"})

        def do_POST(self) -> None:
            if not self.same_origin():
                return
            if not secrets.compare_digest(self.headers.get("X-Crawler-Token", ""), token):
                self.json_response(403, {"error": "Missing or invalid dashboard session token"})
                return
            if self.headers.get("Transfer-Encoding"):
                self.json_response(400, {"error": "Chunked request bodies are unsupported"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 <= length <= 65_536:
                    raise ValueError("Request body is too large")
                payload = json.loads(self.rfile.read(length) or b"{}")
                path = urlsplit(self.path).path
                if path == "/api/scans":
                    scan_id = manager.start(config_from_payload(payload))
                    self.json_response(202, {"id": scan_id})
                elif re.fullmatch(r"/api/scans/[a-f0-9]{16}/stop", path):
                    stopped = manager.stop(path.split("/")[3])
                    self.json_response(200 if stopped else 404, {"stopped": stopped})
                else:
                    self.json_response(404, {"error": "Not found"})
            except (ValueError, TypeError, re.error) as exc:
                self.json_response(400, {"error": str(exc)})
            except RuntimeError as exc:
                self.json_response(409, {"error": str(exc)})

    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    return server


def serve(port: int = 8765, output: Path = Path("reports")) -> None:
    server = make_server("127.0.0.1", port, output.resolve())
    print(f"Scope Crawler dashboard: http://127.0.0.1:{server.server_address[1]}", flush=True)
    print(f"Reports: {output.resolve()}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nDashboard stopped.")
    finally:
        server.server_close()

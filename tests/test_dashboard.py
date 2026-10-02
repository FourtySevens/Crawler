import threading
import time

import httpx
import pytest

from crawler.cli import main as cli_main
from crawler.server import make_server
from examples.demo_site import make_demo_server


@pytest.fixture
def servers(tmp_path):
    demo = make_demo_server(0)
    dashboard = make_server("127.0.0.1", 0, tmp_path)
    threads = []
    for server in (demo, dashboard):
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        threads.append(thread)
    yield f"http://127.0.0.1:{dashboard.server_address[1]}", f"http://127.0.0.1:{demo.server_address[1]}"
    for server, thread in zip((demo, dashboard), threads):
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_dashboard_scan_and_reports_over_real_http(servers):
    dashboard, target = servers
    with httpx.Client(base_url=dashboard, trust_env=False) as client:
        home = client.get("/")
        assert home.status_code == 200
        assert "See your application clearly" in home.text
        assert "frame-ancestors 'none'" in home.headers["content-security-policy"]
        assert client.get("/app.js").status_code == 200
        assert client.get("/style.css").status_code == 200
        token = client.get("/api/session").json()["token"]
        started = client.post("/api/scans", headers={"X-Crawler-Token": token}, json={"url": target, "rate": 500, "max_pages": 100})
        assert started.status_code == 202, started.text
        scan_id = started.json()["id"]
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            job = client.get(f"/api/scans/{scan_id}").json()
            if job["status"] not in {"running", "stopping"}:
                break
            time.sleep(0.03)
        assert job["status"] == "complete", job
        assert job["summary"]["pages"] >= 15
        assert job["summary"]["severity"]["high"] == 1
        report = client.get(f"/reports/{scan_id}/report.json").json()
        assert any(page["url"].endswith("/internal/status") for page in report["pages"])
        assert any(f["rule"] == "error-disclosure" for f in report["findings"])
        assert report["stop_reason"] == "frontier_exhausted"
        assert "demo-value" not in str(report)
        html = client.get(f"/reports/{scan_id}/report.html")
        assert html.status_code == 200
        assert "Password form" in html.text
        assert client.get("/api/scans").json()[0]["id"] == scan_id


def test_dashboard_rejects_csrf_rebinding_and_invalid_requests(servers):
    dashboard, target = servers
    with httpx.Client(base_url=dashboard, trust_env=False) as client:
        assert client.get("/api/session", headers={"Host": "attacker.test"}).status_code == 403
        assert client.get("/api/session", headers={"Origin": "https://attacker.test"}).status_code == 403
        assert client.get("/api/session", headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403
        assert client.get("/", headers={"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate"}).status_code == 200
        assert client.post("/api/scans", json={"url": target}).status_code == 403
        token = client.get("/api/session").json()["token"]
        headers = {"X-Crawler-Token": token}
        assert client.post("/api/scans", headers=headers, json={"url": "file:///etc/passwd"}).status_code == 400
        assert client.post("/api/scans", headers=headers, json={"url": target, "excludes": ["["]}).status_code == 400
        assert client.post("/api/scans", headers=headers, json={"url": target, "concurrency": 1000}).status_code == 400
        assert client.post("/api/scans", headers=headers, content="not json").status_code == 400
        assert client.get("/reports/0000000000000000/report.json").status_code == 404
        assert client.get("/reports/%2e%2e/pyproject.toml").status_code == 404


def test_cli_scan_report_and_finding_exit_code(servers, tmp_path, capsys):
    _, target = servers
    output = tmp_path / "cli-report"
    code = cli_main(["crawl", target, "--rate", "500", "--output", str(output), "--fail-on", "high"])
    assert code == 2
    assert (output / "report.json").is_file()
    assert (output / "report.html").is_file()
    captured = capsys.readouterr()
    assert "frontier_exhausted" in captured.out
    assert "Responses:" in captured.err

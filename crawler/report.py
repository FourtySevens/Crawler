from __future__ import annotations

from collections import Counter
import html
import json
from pathlib import Path
import re

from .models import ScanResult
from .urls import SENSITIVE_NAME, redact_url


SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def sanitize(value, key: str = ""):
    if isinstance(value, dict):
        return {
            k: "[REDACTED]" if key == "headers" and (SENSITIVE_NAME.search(k) or k.lower() in {"set-cookie", "authorization", "proxy-authorization"}) else sanitize(v, k)
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [sanitize(item, key) for item in value]
    if isinstance(value, str):
        return re.sub(r"https?://[^\s<>\"']+", lambda match: redact_url(match.group()), value)
    return value


def summary(result: ScanResult) -> dict:
    return {
        "pages": len(result.pages), "discovered": len(result.discovered),
        "requests": result.requests, "findings": len(result.findings),
        "forms": sum(len(page.forms) for page in result.pages),
        "errors": sum(bool(page.error) for page in result.pages),
        "severity": dict(Counter(f.severity for f in result.findings)),
        "states": dict(Counter(item["state"] for item in result.discovered)),
        "status_codes": dict(Counter(str(page.status) for page in result.pages if page.status)),
        "unique_paths": len({page.url.split("?", 1)[0] for page in result.pages}),
    }


def public_report(result: ScanResult) -> dict:
    data = sanitize(result.to_dict())
    data["schema_version"] = 1
    data["summary"] = summary(result)
    return data


def render_html(data: dict) -> str:
    e = lambda value: html.escape(str(value), quote=True)
    counts = data["summary"]
    cards = "".join(f'<div class="stat"><b>{counts[key]:,}</b><span>{label}</span></div>' for key, label in [("pages", "Responses"), ("discovered", "URLs discovered"), ("findings", "Finding instances"), ("forms", "Forms")])
    findings = []
    groups: dict[tuple, list] = {}
    for finding in sorted(data["findings"], key=lambda f: SEVERITY_ORDER[f["severity"]]):
        groups.setdefault((finding["rule"], finding["severity"]), []).append(finding)
    for (_, severity), group in groups.items():
        first = group[0]
        instances = "".join(f'<tr><td class="url">{e(f["url"])}</td><td>{e(f["confidence"])}</td><td>{e(f["evidence"])}</td></tr>' for f in group)
        findings.append(f'<details class="finding" data-search="{e(first["title"])}"><summary><span class="badge {e(severity)}">{e(severity)}</span> {e(first["title"])} <small>{len(group)} instances</small></summary><p>{e(first["recommendation"])}</p><p><a href="{e(first["reference"])}" rel="noreferrer">Remediation reference</a></p><div class="scroll"><table><thead><tr><th>URL</th><th>Confidence</th><th>Evidence</th></tr></thead><tbody>{instances}</tbody></table></div></details>')
    rows = "".join(f'<tr data-search="{e(p["url"] + " " + p["title"])}"><td>{e(p["status"] or "ERR")}</td><td class="url">{e(p["url"])}</td><td>{e(p["title"] or p["error"] or "—")}</td><td>{e(p["content_type"])}</td><td>{e(p["depth"])}</td><td>{e(p["elapsed_ms"])} ms</td></tr>' for p in data["pages"])
    forms = "".join(f'<tr data-search="{e(p["url"] + " " + f["action"])}"><td class="url">{e(p["url"])}</td><td>{e(f["method"])}</td><td class="url">{e(f["action"])}</td><td>{e(", ".join(x["name"] + " (" + x["type"] + ")" for x in f["fields"]))}</td></tr>' for p in data["pages"] for f in p["forms"])
    coverage = "".join(f'<li>{e(key.replace("_", " "))}: <b>{count}</b></li>' for key, count in sorted(counts["states"].items()))
    warnings = "".join(f'<p class="warning">{e(w)}</p>' for w in data["warnings"])
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>Scope Crawler · {e(data["target"])}</title><style>
:root{{color-scheme:dark}}*{{box-sizing:border-box}}body{{margin:0;background:#0c1420;color:#dce7f2;font:14px/1.6 system-ui,sans-serif}}main{{max-width:1400px;margin:auto;padding:44px 28px}}h1{{font-size:30px;letter-spacing:-1px}}h2{{margin-top:36px}}.eyebrow{{color:#5be0b2;letter-spacing:3px;font-size:12px;font-weight:700}}.muted,small{{color:#93a6bb}}.stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin:28px 0}}.stat,.finding{{background:#131f2f;border:1px solid #29384d;border-radius:10px;padding:20px}}.stat b{{display:block;font-size:32px}}.stat span{{color:#93a6bb}}.finding{{margin:10px 0}}summary{{cursor:pointer;font-weight:600}}summary small{{float:right}}.badge{{display:inline-block;border-radius:5px;padding:2px 8px;margin-right:8px;text-transform:uppercase;font-size:11px;background:#263a50}}.high{{color:#ff8d99;background:#442b37}}.medium{{color:#f4c477;background:#403629}}.low{{color:#7ec6fb;background:#203a50}}.info{{color:#b5b9d6}}.scroll{{overflow:auto}}table{{width:100%;border-collapse:collapse;background:#101b2a}}th,td{{padding:13px;text-align:left;border-bottom:1px solid #29384d;vertical-align:top}}th{{font-size:11px;text-transform:uppercase;color:#93a6bb}}td.url{{word-break:break-all;min-width:200px}}a{{color:#5be0b2}}input{{background:#131f2f;border:1px solid #3c516a;color:inherit;padding:12px;border-radius:8px;width:100%;max-width:460px}}.warning{{color:#f4c477}}ul{{display:flex;gap:24px;flex-wrap:wrap;padding-left:20px}}@media(max-width:650px){{.stats{{grid-template-columns:repeat(2,1fr)}}main{{padding:24px 16px}}}}@media print{{body{{background:white;color:#111}}.stat,.finding,table{{background:white}}details{{break-inside:avoid}}input{{display:none}}}}
</style></head><body><main><div class="eyebrow">SCOPE CRAWLER / PASSIVE ASSESSMENT</div><h1>{e(data["target"])}</h1><p class="muted">Started {e(data["started_at"])} · Finished {e(data["finished_at"])} · {e(data["stop_reason"].replace("_", " "))}</p><div class="stats">{cards}</div>{warnings}
<h2>Coverage</h2><ul>{coverage}</ul><p class="muted">Results cover discovered resources within the configured limits. Finding severity describes potential impact; confidence describes the strength of the observation. Passive findings do not establish exploitability.</p>
<input id="search" aria-label="Filter report" placeholder="Filter URLs, titles, or finding names…">
<h2>Security findings</h2>{''.join(findings) or '<p>No findings observed.</p>'}
<h2>Response inventory</h2><div class="scroll"><table><thead><tr><th>Status</th><th>URL</th><th>Title / error</th><th>Content type</th><th>Depth</th><th>Time</th></tr></thead><tbody>{rows}</tbody></table></div>
<h2>Forms</h2><div class="scroll"><table><thead><tr><th>Page</th><th>Method</th><th>Action</th><th>Fields</th></tr></thead><tbody>{forms}</tbody></table></div><p class="muted">Form values, response bodies, authentication configuration, and cookie values are omitted. Sensitive query values are masked by name.</p>
</main><script>document.getElementById('search').addEventListener('input',function(){{const q=this.value.toLowerCase();document.querySelectorAll('[data-search]').forEach(el=>{{el.hidden=!el.dataset.search.toLowerCase().includes(q)}})}});</script></body></html>'''


def write_reports(result: ScanResult, directory: str | Path) -> tuple[Path, Path]:
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    data = public_report(result)
    json_path, html_path = directory / "report.json", directory / "report.html"
    for path, content in ((json_path, json.dumps(data, indent=2, ensure_ascii=False)), (html_path, render_html(data))):
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(content, encoding="utf-8")
        temporary.replace(path)
    return json_path, html_path

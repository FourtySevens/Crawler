from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit

from bs4 import BeautifulSoup

from .models import Candidate, Extraction, Form
from .urls import is_binary, normalize_url, origin


JS_ENDPOINT = re.compile(
    r"(?:fetch\s*\(|(?:axios|\$)\.(?:get|post|put|delete|patch)\s*\(|\.open\s*\(\s*['\"][A-Z]+['\"]\s*,)\s*['\"]([^'\"\s<>`]+)['\"]"
)
JS_PATH = re.compile(r"['\"]((?:/api/|/graphql|/v[1-9]/)[^'\"\s<>`]{0,500})['\"]")
CSS_URL = re.compile(r"(?:url\(\s*['\"]?([^'\"\s)]+)|@import\s+['\"]([^'\"]+))", re.I)


def extract(url: str, content_type: str, body: str, max_items: int = 5000) -> Extraction:
    result = Extraction()
    seen: set[tuple[str, str]] = set()

    def add(raw: str, kind: str, base: str = url, fetch: bool = True) -> None:
        resolved = normalize_url(raw, base)
        if resolved and (resolved, kind) not in seen and len(result.candidates) < max_items:
            seen.add((resolved, kind))
            result.candidates.append(Candidate(resolved, kind, fetch and not is_binary(resolved)))

    def javascript(source: str, base: str) -> None:
        for pattern in (JS_ENDPOINT, JS_PATH):
            for match in pattern.finditer(source):
                # Inferred API routes are inventoried, not requested automatically:
                # their expected methods/parameters are unknown.
                add(match.group(1), "javascript_endpoint", base, fetch=False)

    mime = content_type.split(";", 1)[0].lower().strip()
    path = urlsplit(url).path.lower()
    is_html = mime in {"text/html", "application/xhtml+xml"} or (not mime and body.lstrip().lower().startswith(("<!doctype html", "<html")))
    if is_html:
        soup = BeautifulSoup(body, "html.parser")
        base_node = soup.find("base", href=True)
        base = normalize_url(str(base_node["href"]), url) if base_node else url
        base = base or url
        result.title = soup.title.get_text(" ", strip=True)[:500] if soup.title else ""
        description = soup.find("meta", attrs={"name": re.compile("^description$", re.I)})
        result.description = str(description.get("content", ""))[:1000] if description else ""
        generator = soup.find("meta", attrs={"name": re.compile("^generator$", re.I)})
        if generator and generator.get("content"):
            result.technologies.append("Generator: " + str(generator["content"])[:200])
        for tag in soup.find_all(["a", "area", "link", "script", "iframe", "frame", "img", "source", "video", "audio", "embed", "object"], limit=max_items):
            attr = "href" if tag.name in {"a", "area", "link"} else "data" if tag.name == "object" else "src"
            raw = str(tag.get(attr, ""))
            if raw.lower().startswith("mailto:"):
                result.emails.append(raw[7:].split("?", 1)[0][:320])
            if raw:
                kind = "link" if tag.name in {"a", "area"} else "script" if tag.name == "script" else "frame" if tag.name in {"iframe", "frame"} else "asset"
                add(raw, kind, base)
                resolved = normalize_url(raw, base)
                if tag.name == "script" and resolved and origin(resolved) != origin(url) and not tag.get("integrity"):
                    result.scripts_without_integrity.append(resolved)
            if tag.get("srcset"):
                for item in str(tag["srcset"]).split(","):
                    bits = item.strip().split()
                    if bits:
                        add(bits[0], "asset", base, fetch=False)
        for tag in soup.find_all("meta", attrs={"http-equiv": re.compile("^refresh$", re.I)}, limit=max_items):
            match = re.search(r"url\s*=\s*['\"]?(.+?)['\"]?$", str(tag.get("content", "")), re.I)
            if match:
                add(match.group(1), "refresh", base)
        for form in soup.find_all("form", limit=max_items):
            # An empty form action resolves to the document, irrespective of <base>.
            action = normalize_url(str(form.get("action", "")), base) if form.get("action") else url
            fields = []
            for field in form.find_all(["input", "textarea", "select", "button"], limit=max_items):
                fields.append({"name": str(field.get("name", ""))[:200], "type": str(field.get("type", field.name)).lower()[:100]})
            method = str(form.get("method", "GET")).upper()
            result.forms.append(Form(action or url, method, str(form.get("enctype", "application/x-www-form-urlencoded")), fields))
            if action:
                add(action, "form_action", fetch=False)
        for script in soup.find_all("script", limit=max_items):
            if not script.get("src"):
                result.inline_script_count += 1
                javascript(script.get_text(), base)
        for style in soup.find_all("style", limit=max_items):
            for match in CSS_URL.finditer(style.get_text()):
                add(match.group(1) or match.group(2), "asset", base)
        result.emails = sorted(set(result.emails))
    elif "javascript" in mime or path.endswith((".js", ".mjs")):
        javascript(body, url)
    elif mime == "text/css" or path.endswith(".css"):
        for match in CSS_URL.finditer(body):
            add(match.group(1) or match.group(2), "asset")
    elif "xml" in mime or path.endswith(".xml"):
        # Do not expand entities from an untrusted sitemap.
        if "<!doctype" not in body.lower() and "<!entity" not in body.lower():
            try:
                root = ET.fromstring(body)
                if root.tag.rsplit("}", 1)[-1] in {"urlset", "sitemapindex"}:
                    for node in root.iter():
                        if node.tag.rsplit("}", 1)[-1] == "loc" and node.text:
                            add(node.text.strip(), "sitemap")
            except (ET.ParseError, ValueError):
                pass
    elif "json" in mime:
        try:
            data = json.loads(body)
            stack = [data]
            count = 0
            while stack and count < max_items:
                current = stack.pop()
                count += 1
                if isinstance(current, dict):
                    for key, value in current.items():
                        if key.lower() in {"href", "url", "next", "previous", "self"} and isinstance(value, str):
                            add(value, "json_link")
                        elif isinstance(value, (dict, list)):
                            stack.append(value)
                elif isinstance(current, list):
                    stack.extend(current[:max_items])
        except (ValueError, RecursionError):
            pass
    if path.endswith("/robots.txt"):
        for line in body.splitlines()[:max_items]:
            name, sep, value = line.partition(":")
            value = value.split("#", 1)[0].strip()
            if sep and value:
                if name.strip().lower() == "sitemap":
                    add(value, "sitemap")
                elif name.strip().lower() in {"allow", "disallow"} and "*" not in value and "$" not in value:
                    add(value, "robots_path")
    return result

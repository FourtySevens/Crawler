from __future__ import annotations

from http.cookies import SimpleCookie
import re
from urllib.parse import urlsplit

import httpx

from .models import Extraction, Finding


HEADERS_REF = "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"
COOKIE_REF = "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"
CSRF_REF = "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"
ERROR_REF = "https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html"


def passive_checks(url: str, status: int, headers: httpx.Headers, body: str, extracted: Extraction) -> list[Finding]:
    findings: list[Finding] = []
    secure = urlsplit(url).scheme == "https"
    mime = headers.get("content-type", "").lower()
    html = "text/html" in mime or "application/xhtml+xml" in mime

    def add(rule: str, severity: str, title: str, evidence: str, advice: str, confidence: str = "high", reference: str = HEADERS_REF) -> None:
        findings.append(Finding(rule, severity, confidence, title, url, evidence[:1000], advice, reference))

    if html and 200 <= status < 300:
        csp = headers.get("content-security-policy", "")
        directives = {part.strip().split()[0].lower(): part.strip().split()[1:] for part in csp.split(";") if part.strip()}
        if not csp:
            add("csp-missing", "low", "Content Security Policy header missing", "No enforcing Content-Security-Policy response header.", "Deploy an enforcing CSP suited to the application. A policy in a meta element may provide partial protection; review it manually.", "medium")
        else:
            script_policy = directives.get("script-src-elem", directives.get("script-src", directives.get("default-src", [])))
            nonce_or_hash = any(value.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for value in script_policy)
            if "'unsafe-inline'" in script_policy and not nonce_or_hash:
                add("csp-inline", "low", "CSP permits inline scripts", "Effective script policy includes 'unsafe-inline' without a nonce or hash.", "Use per-response nonces or hashes for trusted scripts.", "medium")
            if "'unsafe-eval'" in directives.get("script-src", directives.get("default-src", [])):
                add("csp-eval", "low", "CSP permits dynamic code evaluation", "Script policy includes 'unsafe-eval'.", "Remove unsafe-eval after replacing dependencies on string evaluation.")
        if "frame-ancestors" not in directives and headers.get("x-frame-options", "").upper() not in {"DENY", "SAMEORIGIN"}:
            add("frame-protection", "low", "Framing protection missing", "Neither CSP frame-ancestors nor a valid X-Frame-Options header was observed.", "Set CSP frame-ancestors to the origins permitted to embed this page.")
        if headers.get("x-content-type-options", "").lower() != "nosniff":
            add("mime-sniffing", "low", "MIME sniffing protection missing", "X-Content-Type-Options is not nosniff.", "Send X-Content-Type-Options: nosniff with accurate content types.")
        if not headers.get("referrer-policy"):
            add("referrer-policy", "info", "No explicit Referrer-Policy header", "Browser defaults apply; a policy may also exist in HTML.", "Set an explicit Referrer-Policy appropriate to the application's data sensitivity.", "medium")
        if not secure:
            add("unencrypted-page", "medium", "HTML page served over HTTP", "Page content was returned over an unencrypted connection.", "Serve application pages over HTTPS and redirect HTTP traffic.")

    if secure and status < 400:
        hsts = headers.get("strict-transport-security", "")
        match = re.search(r"(?:^|;)\s*max-age\s*=\s*(\d+)\s*(?:;|$)", hsts, re.I)
        if not match or int(match.group(1)) == 0:
            add("hsts-missing", "low", "HSTS protection missing or disabled", "No positive Strict-Transport-Security max-age observed.", "Deploy HSTS after validating HTTPS across the intended scope.")

    for header in ("server", "x-powered-by", "x-aspnet-version"):
        if headers.get(header):
            add("technology-disclosure", "info", "Server technology advertised", f"{header}: {headers[header]}", "Minimize unnecessary version information in response headers.")

    for raw in headers.get_list("set-cookie"):
        cookie = SimpleCookie()
        try:
            cookie.load(raw)
        except Exception:
            continue
        for name, morsel in cookie.items():
            if not morsel["secure"]:
                add("cookie-secure", "low", "Cookie lacks Secure attribute", f"Cookie {name} has no Secure attribute; value omitted.", "Use Secure for cookies that must only travel over HTTPS.", reference=COOKIE_REF)
            if not morsel["httponly"]:
                add("cookie-httponly", "low", "Cookie is accessible to scripts", f"Cookie {name} has no HttpOnly attribute; value omitted.", "Use HttpOnly for session cookies that JavaScript does not need to access.", "medium", COOKIE_REF)
            if morsel["samesite"].lower() not in {"lax", "strict", "none"}:
                add("cookie-samesite", "low", "Cookie lacks an explicit SameSite policy", f"Cookie {name} has no valid explicit SameSite attribute.", "Choose an explicit SameSite policy suitable for the application.", "medium", COOKIE_REF)
            if morsel["samesite"].lower() == "none" and not morsel["secure"]:
                add("cookie-samesite-none", "low", "SameSite=None cookie lacks Secure", f"Cookie {name} may be rejected by modern browsers.", "Pair SameSite=None with Secure.", reference=COOKIE_REF)

    for form in extracted.forms:
        password = any(field["type"] == "password" for field in form.fields)
        if password and (not secure or urlsplit(form.action).scheme == "http"):
            add("password-http", "high", "Password form uses an unencrypted page or action", f"Password field on form targeting {form.action}.", "Serve the form and its submission endpoint exclusively over HTTPS.")
        if password and form.method == "GET":
            add("password-get", "medium", "Password form uses GET", f"GET form targeting {form.action} includes a password field.", "Submit passwords using POST over HTTPS; prevent credentials from appearing in URLs.")
        if form.method == "POST" and not any(re.search(r"csrf|xsrf|authenticity|requestverification", field["name"], re.I) for field in form.fields):
            add("csrf-token-not-observed", "info", "No recognizable CSRF token in POST form", f"Form action: {form.action}. No common CSRF field name was observed.", "Verify CSRF protection manually. SameSite cookies, origin checks, or request headers may provide protection.", "low", CSRF_REF)

    if secure and html:
        mixed = sorted({c.url for c in extracted.candidates if c.kind in {"asset", "script", "frame"} and c.url.startswith("http://")})
        if mixed:
            add("mixed-content", "medium", "HTTP resources referenced by an HTTPS page", "Referenced resources: " + ", ".join(mixed[:5]), "Update resource URLs to HTTPS. Browser blocking or CSP upgrades may mitigate individual requests.", "medium")
    if extracted.scripts_without_integrity:
        add("external-script-integrity", "info", "External scripts lack integrity metadata", "Scripts: " + ", ".join(extracted.scripts_without_integrity[:5]), "Consider Subresource Integrity for immutable third-party scripts.", "medium")
    if headers.get("access-control-allow-origin", "") == "*":
        add("cors-wildcard", "info", "Response permits cross-origin reading", "Access-Control-Allow-Origin: *", "Confirm the resource is intended to be publicly readable. A wildcard alone does not prove sensitive data exposure.")
    if re.search(r"Traceback \(most recent call last\)|Fatal error:.*? on line \d+|SQLSTATE\[\w+\]|Exception in thread", body, re.S):
        add("error-disclosure", "medium", "Possible application error details exposed", "Response matches a stack trace or database error signature; body omitted.", "Return generic errors to clients and retain diagnostic details in server logs.", "medium", ERROR_REF)
    if html and re.search(r"<title>\s*Index of /", body, re.I):
        add("directory-listing", "low", "Possible directory listing", "HTML title matches 'Index of /'.", "Disable directory indexing unless the listing is intentional.", "medium")
    return findings

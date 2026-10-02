from __future__ import annotations

import re
from urllib.parse import parse_qsl, quote, unquote, urljoin, urlsplit, urlunsplit


BINARY_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".avif",
    ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp3", ".mp4", ".webm",
    ".wav", ".ogg", ".pdf", ".zip", ".gz", ".tar", ".rar", ".7z", ".exe",
    ".dmg", ".iso", ".docx", ".xlsx", ".pptx",
})
SENSITIVE_NAME = re.compile(
    r"pass(?:word|wd)?|secret|token|auth|session|cookie|api.?key|signature|credential|csrf|xsrf|^key$|^code$", re.I
)


def normalize_url(value: str, base: str | None = None) -> str | None:
    """Canonicalize transport syntax without reordering meaningful query parameters."""
    try:
        value = value.strip()
        if not value or any(ord(c) < 32 for c in value) or "\\" in value:
            return None
        parts = urlsplit(urljoin(base, value) if base else value)
        if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
            return None
        if parts.username is not None or parts.password is not None:
            return None
        host = parts.hostname.encode("idna").decode("ascii").lower().rstrip(".")
        if not host or any(c.isspace() for c in host) or "%" in host:
            return None
        if ":" in host:
            host = f"[{host}]"
        port = parts.port
        scheme = parts.scheme.lower()
        authority = host if port is None or port == {"http": 80, "https": 443}[scheme] else f"{host}:{port}"
        path = quote(parts.path or "/", safe="/%:@!$&'()*+,;=-._~")
        query = quote(parts.query, safe="%=&?/:;+,$@!'()*-._~")
        return urlunsplit((scheme, authority, path, query, ""))
    except (ValueError, UnicodeError):
        return None


def origin(url: str) -> str:
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}"


def is_binary(url: str) -> bool:
    path = urlsplit(url).path.lower()
    return any(path.endswith(ext) for ext in BINARY_EXTENSIONS)


def parameter_names(url: str) -> list[str]:
    return sorted({name for name, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)})


def redact_url(url: str) -> str:
    # Preserve raw encoding/order for reproducibility; mask sensitive query values.
    try:
        p = urlsplit(url)
        fields = []
        for part in p.query.split("&"):
            key, sep, value = part.partition("=")
            fields.append(key + sep + ("REDACTED" if sep and SENSITIVE_NAME.search(unquote(key)) else value))
        return urlunsplit((p.scheme, p.netloc, p.path, "&".join(fields), p.fragment))
    except ValueError:
        return "[invalid URL]"


class Scope:
    def __init__(self, seed: str, allowed_origins: list[str], subdomains: bool, excludes: list[str]):
        self.seed = seed
        self.origins = {origin(seed)}
        for item in allowed_origins:
            normalized = normalize_url(item)
            if normalized is None:
                raise ValueError(f"Invalid allowed origin: {item}")
            self.origins.add(origin(normalized))
        self.subdomains = subdomains
        self.excludes = [re.compile(pattern) for pattern in excludes]

    def reason(self, url: str) -> str | None:
        p, root = urlsplit(url), urlsplit(self.seed)
        allowed = origin(url) in self.origins
        # Permit the conventional HTTP -> HTTPS upgrade, but no arbitrary ports.
        allowed |= root.scheme == "http" and root.port is None and p.scheme == "https" and p.port is None and p.hostname == root.hostname
        if self.subdomains and p.hostname and root.hostname:
            allowed |= p.hostname.endswith("." + root.hostname) and (p.scheme, p.port) == (root.scheme, root.port)
        if not allowed:
            return "out_of_scope"
        if any(pattern.search(url) for pattern in self.excludes):
            return "excluded"
        return None

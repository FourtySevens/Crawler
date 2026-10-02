from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import math


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Config:
    url: str
    max_pages: int = 1000
    max_depth: int = 12
    concurrency: int = 5
    rate: float = 5.0
    timeout: float = 15.0
    max_duration: float = 900.0
    max_body_bytes: int = 2_000_000
    max_discovered: int = 20_000
    max_variants: int = 20
    retries: int = 2
    include_subdomains: bool = False
    allowed_origins: list[str] = field(default_factory=list)
    excludes: list[str] = field(default_factory=list)
    respect_robots: bool = False
    discover_sitemaps: bool = True
    verify_tls: bool = True
    proxy: str | None = None
    headers: dict[str, str] = field(default_factory=dict, repr=False)
    cookies: dict[str, str] = field(default_factory=dict, repr=False)
    user_agent: str = "ScopeCrawler/0.1 (+passive-security-assessment)"

    def __post_init__(self) -> None:
        for name in ("max_pages", "concurrency", "max_body_bytes", "max_discovered", "max_variants"):
            if getattr(self, name) < 1:
                raise ValueError(f"{name} must be at least 1")
        for name in ("max_depth", "retries"):
            if getattr(self, name) < 0:
                raise ValueError(f"{name} must not be negative")
        for name in ("rate", "timeout", "max_duration"):
            value = getattr(self, name)
            if not math.isfinite(value) or value <= 0:
                raise ValueError(f"{name} must be a finite number greater than zero")


@dataclass
class Candidate:
    url: str
    kind: str
    fetch: bool = True


@dataclass
class Form:
    action: str
    method: str
    enctype: str
    fields: list[dict[str, str]]


@dataclass
class Extraction:
    title: str = ""
    description: str = ""
    candidates: list[Candidate] = field(default_factory=list)
    forms: list[Form] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    scripts_without_integrity: list[str] = field(default_factory=list)
    inline_script_count: int = 0


@dataclass
class Page:
    url: str
    depth: int
    source: str | None = None
    status: int | None = None
    content_type: str = ""
    title: str = ""
    description: str = ""
    size: int = 0
    elapsed_ms: float = 0
    headers: dict[str, str] = field(default_factory=dict)
    forms: list[Form] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    parameters: list[str] = field(default_factory=list)
    redirect_to: str | None = None
    content_hash: str | None = None
    duplicate_of: str | None = None
    truncated: bool = False
    error: str | None = None


@dataclass
class Finding:
    rule: str
    severity: str
    confidence: str
    title: str
    url: str
    evidence: str
    recommendation: str
    reference: str


@dataclass
class ScanResult:
    target: str
    started_at: str = field(default_factory=utc_now)
    finished_at: str | None = None
    stop_reason: str = "running"
    pages: list[Page] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    discovered: list[dict] = field(default_factory=list)
    edges: list[dict[str, str]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    requests: int = 0
    settings: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

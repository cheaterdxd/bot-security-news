from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class ItemKind(str, Enum):
    CVE = "cve"
    KEV = "kev"
    NEWS = "news"


@dataclass(slots=True)
class SecurityItem:
    source: str
    source_id: str
    title: str
    url: str
    published_at: datetime
    kind: ItemKind
    summary: str = ""
    cve_id: str | None = None
    cvss_score: float | None = None
    cvss_severity: str | None = None
    epss_probability: float | None = None
    is_kev: bool = False
    vendor_project: str | None = None
    product: str | None = None
    reasons: list[str] = field(default_factory=list)

    @property
    def stable_id(self) -> str:
        if self.cve_id:
            return self.cve_id.upper()
        return f"{self.source}:{self.source_id}"

    @property
    def published_iso(self) -> str:
        return self.published_at.astimezone(timezone.utc).isoformat()


@dataclass(frozen=True, slots=True)
class FeedConfig:
    name: str
    url: str


@dataclass(frozen=True, slots=True)
class RiskConfig:
    cvss_min: float
    epss_min: float
    rss_keywords: tuple[str, ...]
    urgent_cvss_min: float = 9.0
    rce_keywords: tuple[str, ...] = (
        "remote code execution",
        "rce",
        "arbitrary code execution",
        "code execution",
        "execute arbitrary code",
    )
    exploitation_keywords: tuple[str, ...] = (
        "exploited in the wild",
        "active exploitation",
        "actively exploited",
        "under active exploitation",
        "exploited for",
        "exploited to",
    )


@dataclass(frozen=True, slots=True)
class GitHubPagesConfig:
    remote_url: str
    base_url: str
    branch: str
    docs_dir: str


@dataclass(frozen=True, slots=True)
class AppConfig:
    lookback_hours: int
    database_path: str
    http_timeout_seconds: float
    risk: RiskConfig
    rss_feeds: tuple[FeedConfig, ...]
    github_pages: GitHubPagesConfig

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv

from .models import AppConfig, FeedConfig, GitHubPagesConfig, RiskConfig


DEFAULT_CONFIG_PATH = Path("config.yaml")


def load_config(path: Path = DEFAULT_CONFIG_PATH) -> AppConfig:
    load_dotenv()
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    risk = raw.get("risk") or {}
    feeds = raw.get("rss_feeds") or []
    github_pages = raw.get("github_pages") or {}

    return AppConfig(
        lookback_hours=_as_int(raw, "lookback_hours", 24),
        database_path=str(raw.get("database_path") or "data/security_news.sqlite3"),
        http_timeout_seconds=float(raw.get("http_timeout_seconds") or 30),
        risk=RiskConfig(
            cvss_min=float(risk.get("cvss_min") or 8.0),
            epss_min=float(risk.get("epss_min") or 0.5),
            rss_keywords=tuple(str(x).lower() for x in risk.get("rss_keywords", [])),
            urgent_cvss_min=float(risk.get("urgent_cvss_min") or 9.0),
            rce_keywords=tuple(str(x).lower() for x in risk.get("rce_keywords", _default_rce_keywords())),
            exploitation_keywords=tuple(
                str(x).lower() for x in risk.get("exploitation_keywords", _default_exploitation_keywords())
            ),
        ),
        rss_feeds=tuple(
            FeedConfig(name=str(feed["name"]), url=str(feed["url"]))
            for feed in feeds
            if feed.get("name") and feed.get("url")
        ),
        github_pages=GitHubPagesConfig(
            remote_url=str(github_pages.get("remote_url") or ""),
            base_url=str(github_pages.get("base_url") or ""),
            branch=str(github_pages.get("branch") or "main"),
            docs_dir=str(github_pages.get("docs_dir") or "docs"),
        ),
    )


def _as_int(raw: dict[str, Any], key: str, default: int) -> int:
    value = raw.get(key, default)
    return int(value)


def _default_rce_keywords() -> tuple[str, ...]:
    return (
        "remote code execution",
        "rce",
        "arbitrary code execution",
        "code execution",
        "execute arbitrary code",
    )


def _default_exploitation_keywords() -> tuple[str, ...]:
    return (
        "exploited in the wild",
        "active exploitation",
        "actively exploited",
        "under active exploitation",
        "exploited for",
        "exploited to",
    )

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from html import unescape
import re
from typing import Any

import feedparser

from ..models import FeedConfig, ItemKind, SecurityItem


def fetch_rss_items(feeds: tuple[FeedConfig, ...], lookback_hours: int) -> list[SecurityItem]:
    cutoff = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
    items: list[SecurityItem] = []
    for feed in feeds:
        parsed = feedparser.parse(feed.url)
        for entry in parsed.entries:
            item = _parse_entry(feed, entry)
            if item.published_at >= cutoff:
                items.append(item)
    return items


def _parse_entry(feed: FeedConfig, entry: Any) -> SecurityItem:
    link = str(getattr(entry, "link", "") or getattr(entry, "id", ""))
    title = str(getattr(entry, "title", "Untitled security news"))
    summary = _clean_summary(str(getattr(entry, "summary", "")))
    published = _entry_datetime(entry)
    source_id = str(getattr(entry, "id", "") or link or title)
    return SecurityItem(
        source=feed.name,
        source_id=source_id,
        title=title,
        url=link,
        published_at=published,
        kind=ItemKind.NEWS,
        summary=summary,
    )


def _entry_datetime(entry: Any) -> datetime:
    for attr in ("published", "updated", "created"):
        value = getattr(entry, attr, None)
        if not value:
            continue
        try:
            parsed = parsedate_to_datetime(str(value))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except (TypeError, ValueError):
            continue
    return datetime.now(timezone.utc)


def _clean_summary(value: str) -> str:
    without_tags = re.sub(r"<[^>]+>", " ", value)
    return " ".join(unescape(without_tags).split())

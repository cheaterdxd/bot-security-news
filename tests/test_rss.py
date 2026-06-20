from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from bot_security_news.collectors import rss
from bot_security_news.models import FeedConfig


def test_fetch_rss_items_filters_entries_outside_lookback(monkeypatch):
    now = datetime.now(timezone.utc)
    recent = SimpleNamespace(
        id="recent",
        link="https://example.test/recent",
        title="Recent ransomware item",
        summary="",
        published=now.strftime("%a, %d %b %Y %H:%M:%S +0000"),
    )
    old = SimpleNamespace(
        id="old",
        link="https://example.test/old",
        title="Old breach item",
        summary="",
        published=(now - timedelta(days=3)).strftime("%a, %d %b %Y %H:%M:%S +0000"),
    )
    monkeypatch.setattr(rss.feedparser, "parse", lambda _: SimpleNamespace(entries=[recent, old]))

    items = rss.fetch_rss_items((FeedConfig("Example", "https://example.test/feed"),), lookback_hours=24)

    assert [item.source_id for item in items] == ["recent"]


def test_fetch_rss_items_cleans_html_summary(monkeypatch):
    now = datetime.now(timezone.utc)
    entry = SimpleNamespace(
        id="recent",
        link="https://example.test/recent",
        title="Recent breach item",
        summary="<p>Credential &amp; token leak</p>",
        published=now.strftime("%a, %d %b %Y %H:%M:%S +0000"),
    )
    monkeypatch.setattr(rss.feedparser, "parse", lambda _: SimpleNamespace(entries=[entry]))

    items = rss.fetch_rss_items((FeedConfig("Example", "https://example.test/feed"),), lookback_hours=24)

    assert items[0].summary == "Credential & token leak"

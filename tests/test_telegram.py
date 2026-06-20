from datetime import datetime, timezone

from bot_security_news.models import ItemKind, SecurityItem
from bot_security_news.telegram import (
    ITEM_SEPARATOR,
    TELEGRAM_LIMIT,
    render_digest,
    render_digest_messages,
    render_report_summary,
)


def test_render_digest_groups_items_and_fits_limit():
    items = [
        SecurityItem(
            source="NVD",
            source_id="CVE-2026-0001",
            title="CVE-2026-0001",
            url="https://example.test/cve",
            published_at=datetime.now(timezone.utc),
            kind=ItemKind.CVE,
            cve_id="CVE-2026-0001",
            cvss_score=9.8,
            reasons=["CVSS 9.8 CRITICAL"],
        ),
        SecurityItem(
            source="CISA KEV",
            source_id="CVE-2026-0002",
            title="Vendor Product exploited",
            url="https://example.test/kev",
            published_at=datetime.now(timezone.utc),
            kind=ItemKind.KEV,
            cve_id="CVE-2026-0002",
            is_kev=True,
            reasons=["CISA KEV"],
        ),
    ]

    message = render_digest(items)
    assert "Known Exploited" in message
    assert "Critical/High CVE" in message
    assert ITEM_SEPARATOR in message
    assert len(message) <= TELEGRAM_LIMIT


def test_render_digest_does_not_cut_item_midway():
    items = [
        SecurityItem(
            source="RSS",
            source_id=str(index),
            title=f"Ransomware breach item {index}",
            url=f"https://example.test/{index}",
            published_at=datetime.now(timezone.utc),
            kind=ItemKind.NEWS,
            summary="x" * 500,
            reasons=["keyword: ransomware"],
        )
        for index in range(50)
    ]

    messages = render_digest_messages(items)

    assert all(len(message.text) <= TELEGRAM_LIMIT for message in messages)
    assert all("[Digest truncated" not in message.text for message in messages)
    assert all("more high-risk items not shown" not in message.text for message in messages)
    assert len(messages) == 17


def test_render_digest_messages_keeps_all_items():
    items = [
        SecurityItem(
            source="RSS",
            source_id=str(index),
            title=f"Ransomware breach item {index}",
            url=f"https://example.test/{index}",
            published_at=datetime.now(timezone.utc),
            kind=ItemKind.NEWS,
            reasons=["keyword: ransomware"],
        )
        for index in range(6)
    ]

    messages = render_digest_messages(items)

    assert sum(len(message.items) for message in messages) == 6
    assert len(messages) == 2


def test_render_digest_messages_splits_three_items_per_message():
    items = [
        SecurityItem(
            source="RSS",
            source_id=str(index),
            title=f"Ransomware breach item {index}",
            url=f"https://example.test/{index}",
            published_at=datetime.now(timezone.utc),
            kind=ItemKind.NEWS,
            reasons=["keyword: ransomware"],
        )
        for index in range(6)
    ]

    messages = render_digest_messages(items)

    assert len(messages) == 2
    assert [len(message.items) for message in messages] == [3, 3]
    assert messages[0].text.count(ITEM_SEPARATOR) == 2
    assert "Daily Cybersecurity Digest (1/2)" in messages[0].text
    assert "Daily Cybersecurity Digest (2/2)" in messages[1].text


def test_render_report_summary_includes_counts_and_link():
    message = render_report_summary(
        "https://example.github.io/security-news/reports/2026-06-20.html",
        total_count=10,
        urgent_count=2,
        cve_count=7,
        news_count=3,
    )

    assert "Total collected: 10" in message
    assert "Urgent RCE exploited: 2" in message
    assert "Read full report: https://example.github.io/security-news/reports/2026-06-20.html" in message

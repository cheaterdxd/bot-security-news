from datetime import datetime, timezone

from bot_security_news.models import ItemKind, SecurityItem
from bot_security_news.store import Store


def test_store_filters_sent_items(tmp_path):
    store = Store(str(tmp_path / "state.sqlite3"))
    item = SecurityItem(
        source="NVD",
        source_id="CVE-2026-0001",
        title="CVE-2026-0001",
        url="https://example.test",
        published_at=datetime.now(timezone.utc),
        kind=ItemKind.CVE,
        cve_id="CVE-2026-0001",
    )
    store.upsert_items([item])
    assert store.filter_unsent([item]) == [item]
    store.mark_sent([item])
    assert store.filter_unsent([item]) == []
    store.close()


def test_store_tracks_report_summary_hash(tmp_path):
    store = Store(str(tmp_path / "state.sqlite3"))

    assert store.should_send_report_summary("2026-06-20", "hash-a") is True
    store.mark_report_summary_sent("2026-06-20", "hash-a")
    assert store.should_send_report_summary("2026-06-20", "hash-a") is False
    assert store.should_send_report_summary("2026-06-20", "hash-b") is True
    store.close()

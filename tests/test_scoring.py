from datetime import datetime, timezone

from bot_security_news.models import ItemKind, RiskConfig, SecurityItem
from bot_security_news.scoring import score_items


def _item(**kwargs):
    defaults = {
        "source": "test",
        "source_id": "id",
        "title": "test item",
        "url": "https://example.test",
        "published_at": datetime.now(timezone.utc),
        "kind": ItemKind.CVE,
    }
    defaults.update(kwargs)
    return SecurityItem(**defaults)


def test_includes_kev_even_without_cvss():
    risk = RiskConfig(cvss_min=8.0, epss_min=0.5, rss_keywords=())
    items = score_items([_item(is_kev=True)], risk)
    assert len(items) == 1
    assert "CISA KEV" in items[0].reasons


def test_includes_high_cvss():
    risk = RiskConfig(cvss_min=8.0, epss_min=0.5, rss_keywords=())
    items = score_items([_item(cvss_score=9.8, cvss_severity="CRITICAL")], risk)
    assert len(items) == 1
    assert items[0].reasons == ["CVSS 9.8 CRITICAL"]


def test_filters_low_signal_cve():
    risk = RiskConfig(cvss_min=8.0, epss_min=0.5, rss_keywords=())
    assert score_items([_item(cvss_score=5.0)], risk) == []


def test_includes_rss_keyword():
    risk = RiskConfig(cvss_min=8.0, epss_min=0.5, rss_keywords=("ransomware",))
    news = _item(kind=ItemKind.NEWS, title="Major ransomware breach")
    items = score_items([news], risk)
    assert len(items) == 1
    assert items[0].reasons == ["keyword: ransomware"]

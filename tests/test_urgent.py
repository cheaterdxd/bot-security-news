from datetime import datetime, timezone

from bot_security_news.models import ItemKind, RiskConfig, SecurityItem
from bot_security_news.scoring import filter_urgent_items


def _risk():
    return RiskConfig(cvss_min=8.0, epss_min=0.5, rss_keywords=())


def _item(**kwargs):
    defaults = {
        "source": "NVD",
        "source_id": "CVE-2026-0001",
        "title": "CVE-2026-0001",
        "url": "https://example.test",
        "published_at": datetime.now(timezone.utc),
        "kind": ItemKind.CVE,
        "cve_id": "CVE-2026-0001",
        "cvss_score": 9.8,
        "cvss_severity": "CRITICAL",
        "summary": "Remote code execution exploited in the wild.",
    }
    defaults.update(kwargs)
    return SecurityItem(**defaults)


def test_urgent_requires_cvss_rce_and_exploitation_signal():
    urgent = filter_urgent_items([_item()], _risk())

    assert len(urgent) == 1
    assert urgent[0].reasons == ["CVSS 9.8 CRITICAL", "RCE indicator", "active exploitation signal"]


def test_urgent_rejects_cvss_at_threshold():
    assert filter_urgent_items([_item(cvss_score=9.0)], _risk()) == []


def test_urgent_rejects_without_rce():
    item = _item(summary="Privilege escalation actively exploited in the wild.")
    assert filter_urgent_items([item], _risk()) == []


def test_urgent_rejects_without_exploitation_signal():
    item = _item(summary="Remote code execution in a web endpoint.")
    assert filter_urgent_items([item], _risk()) == []


def test_urgent_allows_kev_as_exploitation_signal():
    item = _item(summary="Remote code execution in a web endpoint.", is_kev=True)
    urgent = filter_urgent_items([item], _risk())

    assert len(urgent) == 1
    assert "CISA KEV" in urgent[0].reasons

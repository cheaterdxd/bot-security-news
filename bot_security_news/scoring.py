from __future__ import annotations

from .models import ItemKind, RiskConfig, SecurityItem


def annotate_items(items: list[SecurityItem], risk: RiskConfig) -> list[SecurityItem]:
    for item in items:
        item.reasons = _report_reasons(item, risk)
    return sorted(items, key=_sort_key)


def score_items(items: list[SecurityItem], risk: RiskConfig) -> list[SecurityItem]:
    selected: list[SecurityItem] = []
    for item in items:
        reasons = _signal_reasons(item, risk)
        if not reasons:
            continue
        item.reasons = reasons
        selected.append(item)
    return sorted(selected, key=_sort_key)


def filter_urgent_items(items: list[SecurityItem], risk: RiskConfig) -> list[SecurityItem]:
    selected: list[SecurityItem] = []
    for item in items:
        reasons = urgent_reasons(item, risk)
        if not reasons:
            continue
        item.reasons = reasons
        selected.append(item)
    return sorted(selected, key=_sort_key)


def urgent_reasons(item: SecurityItem, risk: RiskConfig) -> list[str]:
    if item.cvss_score is None or item.cvss_score <= risk.urgent_cvss_min:
        return []

    text = _item_text(item)
    if not _matches(text, risk.rce_keywords):
        return []

    exploitation = "CISA KEV" if item.is_kev or item.kind == ItemKind.KEV else ""
    if not exploitation and not _matches(text, risk.exploitation_keywords):
        return []

    severity = item.cvss_severity or "CRITICAL"
    reasons = [f"CVSS {item.cvss_score:.1f} {severity}", "RCE indicator"]
    reasons.append(exploitation or "active exploitation signal")
    return reasons


def _report_reasons(item: SecurityItem, risk: RiskConfig) -> list[str]:
    reasons = _signal_reasons(item, risk)
    text = _item_text(item)
    if _matches(text, risk.rce_keywords):
        reasons.append("RCE indicator")
    if _matches(text, risk.exploitation_keywords):
        reasons.append("active exploitation signal")
    if not reasons:
        reasons.append("collected")
    return _dedupe_reasons(reasons)


def _signal_reasons(item: SecurityItem, risk: RiskConfig) -> list[str]:
    reasons: list[str] = []
    if item.is_kev or item.kind == ItemKind.KEV:
        reasons.append("CISA KEV")
    if item.cvss_score is not None and item.cvss_score >= risk.cvss_min:
        severity = item.cvss_severity or "High"
        reasons.append(f"CVSS {item.cvss_score:.1f} {severity}")
    if item.epss_probability is not None and item.epss_probability >= risk.epss_min:
        reasons.append(f"EPSS {item.epss_probability:.1%}")
    if item.kind == ItemKind.NEWS:
        text = _item_text(item)
        matched = [keyword for keyword in risk.rss_keywords if keyword in text]
        if matched:
            reasons.append(f"keyword: {matched[0]}")
    return reasons


def _item_text(item: SecurityItem) -> str:
    return f"{item.title} {item.summary} {item.product or ''} {item.vendor_project or ''}".lower()


def _matches(text: str, keywords: tuple[str, ...]) -> bool:
    return any(keyword in text for keyword in keywords)


def _dedupe_reasons(reasons: list[str]) -> list[str]:
    deduped: list[str] = []
    for reason in reasons:
        if reason not in deduped:
            deduped.append(reason)
    return deduped


def _sort_key(item: SecurityItem) -> tuple[int, float, float, str]:
    kev_rank = 0 if item.is_kev or item.kind == ItemKind.KEV else 1
    cvss = -(item.cvss_score or 0)
    epss = -(item.epss_probability or 0)
    return kev_rank, cvss, epss, item.published_iso

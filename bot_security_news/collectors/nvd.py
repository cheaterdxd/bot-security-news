from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any

from ..http_client import get_json
from ..models import ItemKind, SecurityItem


NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_recent_cves(lookback_hours: int, timeout: float) -> list[SecurityItem]:
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=lookback_hours)
    headers = {}
    if api_key := os.getenv("NVD_API_KEY"):
        headers["apiKey"] = api_key

    payload = get_json(
        NVD_URL,
        params={
            "pubStartDate": _nvd_time(start),
            "pubEndDate": _nvd_time(end),
            "resultsPerPage": 2000,
        },
        headers=headers,
        timeout=timeout,
    )
    return [_parse_vulnerability(row) for row in payload.get("vulnerabilities", [])]


def _parse_vulnerability(row: dict[str, Any]) -> SecurityItem:
    cve = row.get("cve", {})
    cve_id = cve.get("id", "unknown-cve")
    descriptions = cve.get("descriptions", [])
    description = next(
        (x.get("value", "") for x in descriptions if x.get("lang") == "en"),
        descriptions[0].get("value", "") if descriptions else "",
    )
    metrics = cve.get("metrics", {})
    score, severity = _extract_cvss(metrics)
    published = _parse_datetime(cve.get("published"))
    references = _extract_references(cve.get("references"))
    url = references[0].get("url") if references else f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    is_kev = bool(cve.get("cisaExploitAdd"))

    return SecurityItem(
        source="NVD",
        source_id=cve_id,
        title=cve_id,
        url=url,
        published_at=published,
        kind=ItemKind.CVE,
        summary=description,
        cve_id=cve_id,
        cvss_score=score,
        cvss_severity=severity,
        is_kev=is_kev,
        vendor_project=cve.get("sourceIdentifier"),
        product=cve.get("cisaVulnerabilityName"),
    )


def _extract_cvss(metrics: dict[str, Any]) -> tuple[float | None, str | None]:
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        data = entries[0].get("cvssData", {})
        score = data.get("baseScore")
        severity = entries[0].get("baseSeverity") or data.get("baseSeverity")
        return (float(score) if score is not None else None), severity
    return None, None


def _extract_references(raw: Any) -> list[dict[str, Any]]:
    if isinstance(raw, list):
        return [item for item in raw if isinstance(item, dict)]
    if isinstance(raw, dict):
        values = raw.get("referenceData") or []
        return [item for item in values if isinstance(item, dict)]
    return []


def _parse_datetime(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    normalized = value.replace("Z", "+00:00")
    return datetime.fromisoformat(normalized).astimezone(timezone.utc)


def _nvd_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")

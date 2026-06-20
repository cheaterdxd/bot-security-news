from __future__ import annotations

from ..http_client import get_json
from ..models import SecurityItem


EPSS_URL = "https://api.first.org/data/v1/epss"


def enrich_with_epss(items: list[SecurityItem], timeout: float) -> list[SecurityItem]:
    cves = sorted({item.cve_id for item in items if item.cve_id})
    if not cves:
        return items

    scores: dict[str, float] = {}
    for chunk in _chunks(cves, 100):
        payload = get_json(EPSS_URL, params={"cve": ",".join(chunk)}, timeout=timeout)
        for row in payload.get("data", []):
            try:
                scores[str(row["cve"]).upper()] = float(row["epss"])
            except (KeyError, TypeError, ValueError):
                continue

    for item in items:
        if item.cve_id and item.cve_id.upper() in scores:
            item.epss_probability = scores[item.cve_id.upper()]
    return items


def _chunks(values: list[str], size: int) -> list[list[str]]:
    return [values[index : index + size] for index in range(0, len(values), size)]

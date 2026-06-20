from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from typing import Any

from ..http_client import get_json
from ..models import ItemKind, SecurityItem


CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_cisa_kev(lookback_hours: int, timeout: float) -> list[SecurityItem]:
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=lookback_hours)).date()
    payload = get_json(CISA_KEV_URL, timeout=timeout)

    items: list[SecurityItem] = []
    for row in payload.get("vulnerabilities", []):
        added = _parse_date(row.get("dateAdded"))
        if added < cutoff:
            continue
        cve_id = str(row.get("cveID") or "unknown-cve")
        vendor = str(row.get("vendorProject") or "")
        product = str(row.get("product") or "")
        vulnerability = str(row.get("vulnerabilityName") or cve_id)
        items.append(
            SecurityItem(
                source="CISA KEV",
                source_id=cve_id,
                title=f"{vendor} {product}: {vulnerability}".strip(),
                url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                published_at=datetime.combine(added, datetime.min.time(), tzinfo=timezone.utc),
                kind=ItemKind.KEV,
                summary=str(row.get("shortDescription") or row.get("requiredAction") or ""),
                cve_id=cve_id,
                is_kev=True,
                vendor_project=vendor,
                product=product,
            )
        )
    return items


def _parse_date(value: Any) -> date:
    if not value:
        return datetime.now(timezone.utc).date()
    return datetime.strptime(str(value), "%Y-%m-%d").date()

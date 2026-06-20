from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from html import escape
from pathlib import Path

from .models import GitHubPagesConfig, ItemKind, SecurityItem


@dataclass(frozen=True, slots=True)
class ReportResult:
    date: date
    docs_dir: Path
    latest_path: Path
    archive_path: Path
    latest_url: str
    archive_url: str
    total_count: int
    urgent_count: int
    cve_count: int
    news_count: int


def generate_html_report(
    items: list[SecurityItem],
    urgent_items: list[SecurityItem],
    github_pages: GitHubPagesConfig,
    report_date: date | None = None,
) -> ReportResult:
    report_date = report_date or date.today()
    docs_dir = Path(github_pages.docs_dir)
    reports_dir = docs_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    urgent_ids = {item.stable_id for item in urgent_items}
    sorted_items = sorted(items, key=lambda item: (item.stable_id not in urgent_ids, -_score(item), item.published_iso))
    html = _render_page(sorted_items, urgent_ids, report_date)

    latest_path = docs_dir / "index.html"
    archive_path = reports_dir / f"{report_date.isoformat()}.html"
    latest_path.write_text(html, encoding="utf-8")
    archive_path.write_text(html, encoding="utf-8")

    return ReportResult(
        date=report_date,
        docs_dir=docs_dir,
        latest_path=latest_path,
        archive_path=archive_path,
        latest_url=_url_join(github_pages.base_url, "index.html"),
        archive_url=_url_join(github_pages.base_url, f"reports/{report_date.isoformat()}.html"),
        total_count=len(items),
        urgent_count=len(urgent_items),
        cve_count=sum(1 for item in items if item.kind in {ItemKind.CVE, ItemKind.KEV}),
        news_count=sum(1 for item in items if item.kind == ItemKind.NEWS),
    )


def _render_page(items: list[SecurityItem], urgent_ids: set[str], report_date: date) -> str:
    cards = "\n".join(_render_item(item, item.stable_id in urgent_ids) for item in items)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Security News Report {escape(report_date.isoformat())}</title>
  <style>
    body {{
      margin: 0;
      font-family: Arial, Helvetica, sans-serif;
      background: #f5f5f5;
      color: #202124;
    }}
    main {{
      max-width: 980px;
      margin: 0 auto;
      padding: 24px 16px 48px;
    }}
    h1 {{
      font-size: 24px;
      margin: 0 0 4px;
    }}
    .meta {{
      color: #5f6368;
      margin: 0 0 20px;
    }}
    .card {{
      background: #ffffff;
      border: 1px solid #dadce0;
      border-radius: 8px;
      padding: 14px 16px;
      margin: 12px 0;
      overflow-wrap: anywhere;
    }}
    .urgent {{
      border-color: #d93025;
    }}
    .badge {{
      display: inline-block;
      border: 1px solid #dadce0;
      border-radius: 999px;
      padding: 2px 8px;
      margin: 0 6px 6px 0;
      font-size: 12px;
      color: #3c4043;
    }}
    .badge.urgent {{
      border-color: #d93025;
      color: #a50e0e;
    }}
    h2 {{
      font-size: 18px;
      margin: 4px 0 8px;
    }}
    p {{
      line-height: 1.45;
    }}
    a {{
      color: #1a73e8;
    }}
  </style>
</head>
<body>
  <main>
    <h1>Security News Report</h1>
    <p class="meta">Generated for {escape(report_date.isoformat())}. Scroll down to read all collected items.</p>
    {cards or "<p>No items collected.</p>"}
  </main>
</body>
</html>
"""


def _render_item(item: SecurityItem, urgent: bool) -> str:
    badges = [
        _badge("URGENT", urgent=True) if urgent else "",
        _badge(item.source),
        _badge(item.kind.value.upper()),
        _badge(item.cve_id or ""),
        _badge(f"CVSS {item.cvss_score:.1f}" if item.cvss_score is not None else ""),
        _badge(f"EPSS {item.epss_probability:.1%}" if item.epss_probability is not None else ""),
        _badge("KEV" if item.is_kev else ""),
    ]
    reasons = ", ".join(item.reasons) if item.reasons else "collected"
    summary = escape(item.summary or "")
    return f"""<article class="card{' urgent' if urgent else ''}">
  <div>{''.join(badges)}</div>
  <h2>{escape(item.title)}</h2>
  <p><strong>Published:</strong> {escape(item.published_iso)}</p>
  <p><strong>Reasons:</strong> {escape(reasons)}</p>
  {f"<p>{summary}</p>" if summary else ""}
  <p><a href="{escape(item.url, quote=True)}" target="_blank" rel="noopener noreferrer">Open source link</a></p>
</article>"""


def _badge(value: str, urgent: bool = False) -> str:
    if not value:
        return ""
    css = "badge urgent" if urgent else "badge"
    return f'<span class="{css}">{escape(value)}</span>'


def _score(item: SecurityItem) -> float:
    return (item.cvss_score or 0) + (item.epss_probability or 0)


def _url_join(base_url: str, path: str) -> str:
    if not base_url:
        return path
    return f"{base_url.rstrip('/')}/{path.lstrip('/')}"

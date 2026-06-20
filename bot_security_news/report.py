from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from html import escape
import json
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
    
    # Save the daily archive report
    archive_path.write_text(html, encoding="utf-8")

    result = ReportResult(
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

    # Update metadata registry and generate landing page (index.html)
    reports_list = _update_reports_json(docs_dir, result)
    landing_html = _render_landing_page(reports_list)
    latest_path.write_text(landing_html, encoding="utf-8")

    return result


def _update_reports_json(docs_dir: Path, new_report: ReportResult) -> list[dict]:
    json_path = docs_dir / "reports.json"
    data = {}
    if json_path.exists():
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            data = {}

    # Backfill existing HTML files in reports directory if not already indexed
    reports_dir = docs_dir / "reports"
    if reports_dir.exists():
        for p in reports_dir.glob("*.html"):
            r_date = p.stem
            try:
                date.fromisoformat(r_date)
            except ValueError:
                continue
            if r_date not in data:
                try:
                    html_content = p.read_text(encoding="utf-8")
                    total_count = html_content.count('class="card')
                    urgent_count = html_content.count('class="card urgent')
                    cve_count = html_content.count('CVE-')
                    data[r_date] = {
                        "date": r_date,
                        "total_count": total_count,
                        "urgent_count": urgent_count,
                        "cve_count": cve_count,
                        "news_count": max(0, total_count - cve_count)
                    }
                except Exception:
                    pass

    # Add/Update the current report entry
    data[new_report.date.isoformat()] = {
        "date": new_report.date.isoformat(),
        "total_count": new_report.total_count,
        "urgent_count": new_report.urgent_count,
        "cve_count": new_report.cve_count,
        "news_count": new_report.news_count,
    }

    # Save reports.json
    try:
        docs_dir.mkdir(parents=True, exist_ok=True)
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass

    reports_list = list(data.values())
    reports_list.sort(key=lambda r: r["date"], reverse=True)
    return reports_list


def _render_landing_page(reports: list[dict]) -> str:
    rows = []
    for r in reports:
        r_date = r["date"]
        total = r["total_count"]
        urgent = r["urgent_count"]
        cves = r["cve_count"]
        news = r["news_count"]
        
        try:
            parsed_date = date.fromisoformat(r_date)
            formatted_date = parsed_date.strftime("%B %d, %Y")
        except Exception:
            formatted_date = r_date
            
        urgent_badge = ""
        if urgent > 0:
            urgent_badge = f'<span class="badge urgent-alert">{urgent} Urgent Alert{"s" if urgent > 1 else ""}</span>'
            card_class = "report-card has-urgent"
        else:
            card_class = "report-card"
            
        rows.append(f"""
      <a href="reports/{r_date}.html" class="{card_class}">
        <div class="card-header">
          <span class="report-date">{formatted_date}</span>
          <div class="badges">
            {urgent_badge}
            <span class="badge badge-cve">{cves} CVEs</span>
            <span class="badge badge-news">{news} News</span>
          </div>
        </div>
        <div class="card-body">
          <div class="stat-group">
            <span class="stat-number">{total}</span>
            <span class="stat-label">Total Items</span>
          </div>
          <div class="view-link">
            <span>View Digest</span>
            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="arrow-icon"><line x1="5" y1="12" x2="19" y2="12"></line><polyline points="12 5 19 12 12 19"></polyline></svg>
          </div>
        </div>
      </a>
        """)
        
    reports_html = "\n".join(rows) if rows else '<div class="no-reports">No reports available yet. Run the collector to generate the first report.</div>'
    
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Security News Digest Center</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Outfit:wght@500;700;800&display=swap" rel="stylesheet">
  <style>
    :root {{
      --bg-color: #0b0f19;
      --bg-gradient: radial-gradient(circle at 50% 0%, #1e1b4b 0%, #0f172a 50%, #0b0f19 100%);
      --card-bg: rgba(17, 24, 39, 0.7);
      --card-border: rgba(255, 255, 255, 0.08);
      --text-primary: #f8fafc;
      --text-secondary: #94a3b8;
      --accent: #6366f1;
      --accent-glow: rgba(99, 102, 241, 0.15);
      --urgent: #f43f5e;
      --urgent-glow: rgba(244, 63, 94, 0.2);
      --success: #10b981;
      --cve: #3b82f6;
    }}
    
    * {{
      box-sizing: border-box;
    }}
    
    body {{
      margin: 0;
      padding: 0;
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background-color: var(--bg-color);
      background-image: var(--bg-gradient);
      color: var(--text-primary);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }}
    
    main {{
      max-width: 800px;
      margin: 0 auto;
      padding: 60px 20px 80px;
      width: 100%;
      flex-grow: 1;
    }}
    
    header {{
      text-align: center;
      margin-bottom: 50px;
    }}
    
    .logo-container {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 64px;
      height: 64px;
      border-radius: 16px;
      background: rgba(99, 102, 241, 0.1);
      border: 1px solid rgba(99, 102, 241, 0.2);
      color: var(--accent);
      margin-bottom: 20px;
      box-shadow: 0 0 20px var(--accent-glow);
    }}
    
    h1 {{
      font-family: 'Outfit', sans-serif;
      font-size: 36px;
      font-weight: 800;
      margin: 0 0 12px;
      background: linear-gradient(135deg, #ffffff 0%, #94a3b8 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      letter-spacing: -0.02em;
    }}
    
    .subtitle {{
      color: var(--text-secondary);
      font-size: 16px;
      margin: 0 auto;
      max-width: 500px;
      line-height: 1.6;
    }}
    
    .reports-list {{
      display: flex;
      flex-direction: column;
      gap: 16px;
      margin-top: 40px;
    }}
    
    .report-card {{
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 16px;
      padding: 20px 24px;
      display: block;
      text-decoration: none;
      color: inherit;
      transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
    }}
    
    .report-card:hover {{
      transform: translateY(-2px);
      border-color: rgba(99, 102, 241, 0.3);
      box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3), 0 8px 10px -6px var(--accent-glow);
      background: rgba(17, 24, 39, 0.85);
    }}
    
    .report-card.has-urgent {{
      border-left: 4px solid var(--urgent);
    }}
    
    .report-card.has-urgent:hover {{
      border-color: rgba(244, 63, 94, 0.5);
      border-left-color: var(--urgent);
      box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3), 0 8px 10px -6px var(--urgent-glow);
    }}
    
    .card-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 16px;
      flex-wrap: wrap;
      gap: 12px;
    }}
    
    .report-date {{
      font-family: 'Outfit', sans-serif;
      font-size: 20px;
      font-weight: 700;
      color: #ffffff;
      letter-spacing: -0.01em;
    }}
    
    .badges {{
      display: flex;
      gap: 8px;
      align-items: center;
    }}
    
    .badge {{
      font-size: 12px;
      font-weight: 600;
      padding: 4px 10px;
      border-radius: 9999px;
      letter-spacing: 0.02em;
    }}
    
    .urgent-alert {{
      background: rgba(244, 63, 94, 0.15);
      color: #fda4af;
      border: 1px solid rgba(244, 63, 94, 0.3);
      box-shadow: 0 0 12px rgba(244, 63, 94, 0.1);
      animation: pulse 2s infinite;
    }}
    
    .badge-cve {{
      background: rgba(59, 130, 246, 0.15);
      color: #93c5fd;
      border: 1px solid rgba(59, 130, 246, 0.3);
    }}
    
    .badge-news {{
      background: rgba(148, 163, 184, 0.1);
      color: #cbd5e1;
      border: 1px solid rgba(148, 163, 184, 0.2);
    }}
    
    .card-body {{
      display: flex;
      justify-content: space-between;
      align-items: flex-end;
    }}
    
    .stat-group {{
      display: flex;
      flex-direction: column;
    }}
    
    .stat-number {{
      font-size: 28px;
      font-weight: 700;
      color: #ffffff;
      line-height: 1.1;
    }}
    
    .stat-label {{
      font-size: 12px;
      color: var(--text-secondary);
      margin-top: 4px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }}
    
    .view-link {{
      display: flex;
      align-items: center;
      gap: 6px;
      color: var(--accent);
      font-size: 14px;
      font-weight: 600;
      transition: gap 0.2s ease;
    }}
    
    .report-card:hover .view-link {{
      gap: 10px;
    }}
    
    .report-card.has-urgent:hover .view-link {{
      color: #fb7185;
    }}
    
    .arrow-icon {{
      transition: transform 0.2s ease;
    }}
    
    .report-card:hover .arrow-icon {{
      transform: translateX(2px);
    }}
    
    .no-reports {{
      text-align: center;
      padding: 40px;
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 16px;
      color: var(--text-secondary);
      font-size: 15px;
      backdrop-filter: blur(12px);
    }}
    
    footer {{
      text-align: center;
      padding: 40px 20px;
      color: #475569;
      font-size: 13px;
      border-top: 1px solid rgba(255, 255, 255, 0.03);
    }}
    
    @keyframes pulse {{
      0% {{
        box-shadow: 0 0 0 0 rgba(244, 63, 94, 0.4);
      }}
      70% {{
        box-shadow: 0 0 0 6px rgba(244, 63, 94, 0);
      }}
      100% {{
        box-shadow: 0 0 0 0 rgba(244, 63, 94, 0);
      }}
    }}
  </style>
</head>
<body>
  <main>
    <header>
      <div class="logo-container">
        <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
      </div>
      <h1>Security News Portal</h1>
      <p class="subtitle">Security alerts and vulnerability updates collected automatically by the Security News Bot.</p>
    </header>
    
    <div class="reports-list">
      {reports_html}
    </div>
  </main>
  
  <footer>
    <p>Powered by Bot Security News. Automatically updated on GitHub Pages.</p>
  </footer>
</body>
</html>
"""


def _render_page(items: list[SecurityItem], urgent_ids: set[str], report_date: date) -> str:
    cards = "\n".join(_render_item(item, item.stable_id in urgent_ids) for item in items)
    
    try:
        formatted_date = report_date.strftime("%B %d, %Y")
    except Exception:
        formatted_date = report_date.isoformat()
        
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Security News Report - {escape(report_date.isoformat())}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Outfit:wght@500;700;800&display=swap" rel="stylesheet">
  <style>
    :root {{
      --bg-color: #0b0f19;
      --bg-gradient: radial-gradient(circle at 50% 0%, #1e1b4b 0%, #0f172a 50%, #0b0f19 100%);
      --card-bg: rgba(17, 24, 39, 0.7);
      --card-border: rgba(255, 255, 255, 0.08);
      --text-primary: #f8fafc;
      --text-secondary: #94a3b8;
      --accent: #6366f1;
      --accent-glow: rgba(99, 102, 241, 0.15);
      --urgent: #f43f5e;
      --urgent-glow: rgba(244, 63, 94, 0.25);
      --success: #10b981;
    }}
    
    * {{
      box-sizing: border-box;
    }}
    
    body {{
      margin: 0;
      padding: 0;
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background-color: var(--bg-color);
      background-image: var(--bg-gradient);
      color: var(--text-primary);
      min-height: 100vh;
    }}
    
    main {{
      max-width: 900px;
      margin: 0 auto;
      padding: 40px 20px 80px;
      width: 100%;
    }}
    
    .nav-bar {{
      margin-bottom: 40px;
    }}
    
    .back-link {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
      color: var(--text-secondary);
      text-decoration: none;
      font-size: 14px;
      font-weight: 500;
      transition: color 0.2s ease;
    }}
    
    .back-link:hover {{
      color: var(--accent);
    }}
    
    header {{
      margin-bottom: 40px;
    }}
    
    h1 {{
      font-family: 'Outfit', sans-serif;
      font-size: 32px;
      font-weight: 800;
      margin: 0 0 10px;
      background: linear-gradient(135deg, #ffffff 0%, #cbd5e1 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      letter-spacing: -0.02em;
    }}
    
    .meta {{
      color: var(--text-secondary);
      font-size: 15px;
      margin: 0;
    }}
    
    .card {{
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 16px;
      padding: 24px;
      margin: 20px 0;
      overflow-wrap: anywhere;
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      transition: transform 0.2s ease, border-color 0.2s ease;
    }}
    
    .card:hover {{
      border-color: rgba(255, 255, 255, 0.15);
    }}
    
    .card.urgent {{
      border-left: 4px solid var(--urgent);
      background: linear-gradient(to right, rgba(244, 63, 94, 0.03), rgba(17, 24, 39, 0.7));
      box-shadow: 0 4px 20px -2px var(--urgent-glow);
    }}
    
    .badge-container {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-bottom: 16px;
    }}
    
    .badge {{
      display: inline-block;
      font-size: 11px;
      font-weight: 600;
      padding: 3px 8px;
      border-radius: 999px;
      letter-spacing: 0.02em;
    }}
    
    .badge-default {{
      background: rgba(148, 163, 184, 0.1);
      color: #cbd5e1;
      border: 1px solid rgba(148, 163, 184, 0.2);
    }}
    
    .badge-urgent {{
      background: rgba(244, 63, 94, 0.15);
      color: #fda4af;
      border: 1px solid rgba(244, 63, 94, 0.3);
    }}
    
    .badge-cve {{
      background: rgba(59, 130, 246, 0.15);
      color: #93c5fd;
      border: 1px solid rgba(59, 130, 246, 0.3);
    }}
    
    .badge-kev {{
      background: rgba(245, 158, 11, 0.15);
      color: #fcd34d;
      border: 1px solid rgba(245, 158, 11, 0.3);
    }}
    
    .badge-cvss {{
      background: rgba(239, 68, 68, 0.15);
      color: #fca5a5;
      border: 1px solid rgba(239, 68, 68, 0.3);
    }}
    
    .badge-epss {{
      background: rgba(168, 85, 247, 0.15);
      color: #d8b4fe;
      border: 1px solid rgba(168, 85, 247, 0.3);
    }}
    
    h2 {{
      font-family: 'Outfit', sans-serif;
      font-size: 20px;
      font-weight: 700;
      margin: 0 0 12px;
      color: #ffffff;
      line-height: 1.4;
    }}
    
    .card-meta {{
      font-size: 13px;
      color: var(--text-secondary);
      margin: 12px 0;
      display: flex;
      flex-direction: column;
      gap: 6px;
    }}
    
    .card-meta strong {{
      color: #cbd5e1;
    }}
    
    p.summary {{
      line-height: 1.6;
      color: #cbd5e1;
      font-size: 14.5px;
      margin: 16px 0;
      background: rgba(0, 0, 0, 0.15);
      padding: 12px 16px;
      border-radius: 8px;
      border-left: 2px solid var(--accent);
    }}
    
    .source-link {{
      display: inline-flex;
      align-items: center;
      gap: 4px;
      color: var(--accent);
      text-decoration: none;
      font-size: 14px;
      font-weight: 600;
      margin-top: 8px;
      transition: color 0.2s ease;
    }}
    
    .source-link:hover {{
      color: #818cf8;
      text-decoration: underline;
    }}
    
    .no-items {{
      text-align: center;
      padding: 40px;
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 16px;
      color: var(--text-secondary);
    }}
  </style>
</head>
<body>
  <main>
    <div class="nav-bar">
      <a href="../index.html" class="back-link">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="19" y1="12" x2="5" y2="12"></line><polyline points="12 19 5 12 12 5"></polyline></svg>
        Back to Reports Portal
      </a>
    </div>
    
    <header>
      <h1>Security News Report</h1>
      <p class="meta">Digest generated for <strong>{escape(formatted_date)}</strong></p>
    </header>
    
    <div class="cards-list">
      {cards or '<div class="no-items">No items collected for this period.</div>'}
    </div>
  </main>
</body>
</html>
"""


def _render_item(item: SecurityItem, urgent: bool) -> str:
    badges = []
    if urgent:
        badges.append(f'<span class="badge badge-urgent">URGENT</span>')
    
    badges.append(f'<span class="badge badge-default">{escape(item.source.upper())}</span>')
    badges.append(f'<span class="badge badge-default">{escape(item.kind.value.upper())}</span>')
    
    if item.cve_id:
        badges.append(f'<span class="badge badge-cve">{escape(item.cve_id)}</span>')
    if item.cvss_score is not None:
        badges.append(f'<span class="badge badge-cvss">CVSS {item.cvss_score:.1f}</span>')
    if item.epss_probability is not None:
        badges.append(f'<span class="badge badge-epss">EPSS {item.epss_probability:.1%}</span>')
    if item.is_kev:
        badges.append(f'<span class="badge badge-kev">KEV</span>')
        
    reasons = ", ".join(item.reasons) if item.reasons else "collected"
    summary = escape(item.summary or "")
    
    return f"""<article class="card{' urgent' if urgent else ''}">
  <div class="badge-container">
    {"".join(badges)}
  </div>
  <h2>{escape(item.title)}</h2>
  <div class="card-meta">
    <div><strong>Published:</strong> {escape(item.published_iso)}</div>
    <div><strong>Reasons:</strong> {escape(reasons)}</div>
  </div>
  {f'<p class="summary">{summary}</p>' if summary else ''}
  <a href="{escape(item.url, quote=True)}" target="_blank" rel="noopener noreferrer" class="source-link">
    Open Source Link
    <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path><polyline points="15 3 21 3 21 9"></polyline><line x1="10" y1="14" x2="21" y2="3"></line></svg>
  </a>
</article>"""


def _score(item: SecurityItem) -> float:
    return (item.cvss_score or 0) + (item.epss_probability or 0)


def _url_join(base_url: str, path: str) -> str:
    if not base_url:
        return path
    return f"{base_url.rstrip('/')}/{path.lstrip('/')}"


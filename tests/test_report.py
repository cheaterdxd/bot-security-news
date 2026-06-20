from datetime import date, datetime, timezone

from bot_security_news.models import GitHubPagesConfig, ItemKind, SecurityItem
from bot_security_news.report import generate_html_report


def test_generate_html_report_writes_latest_and_archive_and_escapes_content(tmp_path):
    item = SecurityItem(
        source="RSS",
        source_id="1",
        title="<script>alert(1)</script>",
        url="https://example.test/?q=<bad>",
        published_at=datetime.now(timezone.utc),
        kind=ItemKind.NEWS,
        summary="<b>breach</b>",
        reasons=["keyword: breach"],
    )
    cfg = GitHubPagesConfig(
        remote_url="https://github.com/example/security-news.git",
        base_url="https://example.github.io/security-news",
        branch="main",
        docs_dir=str(tmp_path / "docs"),
    )

    report = generate_html_report([item], [], cfg, report_date=date(2026, 6, 20))

    assert report.latest_path.exists()
    assert report.archive_path.exists()
    assert report.archive_url == "https://example.github.io/security-news/reports/2026-06-20.html"
    
    # Assert escaping in the actual daily report archive path
    html = report.archive_path.read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "&lt;b&gt;breach&lt;/b&gt;" in html

    # Assert the index landing page references the report
    index_html = report.latest_path.read_text(encoding="utf-8")
    assert "reports/2026-06-20.html" in index_html
    assert "June 20, 2026" in index_html


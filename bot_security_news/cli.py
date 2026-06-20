from __future__ import annotations

from pathlib import Path
import hashlib

import typer
from rich.console import Console
from rich.table import Table

from .collectors import enrich_with_epss, fetch_cisa_kev, fetch_recent_cves, fetch_rss_items
from .config import DEFAULT_CONFIG_PATH, load_config
from .models import SecurityItem
from .publisher import publish_report
from .report import generate_html_report
from .scoring import annotate_items, filter_urgent_items
from .store import Store
from .telegram import render_digest_messages, render_report_summary, send_message


app = typer.Typer(help="Collect cybersecurity news, publish HTML reports, and send urgent Telegram alerts.")
console = Console()


@app.command()
def collect(
    config: Path = typer.Option(DEFAULT_CONFIG_PATH, "--config", "-c", help="Path to config.yaml."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Print digest without sending Telegram."),
) -> None:
    cfg = load_config(config)
    items = annotate_items(_collect_items(cfg), cfg.risk)
    urgent = filter_urgent_items(items, cfg.risk)
    report = generate_html_report(items, urgent, cfg.github_pages)
    content_hash = _content_hash(items)
    summary_message = render_report_summary(
        report.archive_url,
        report.total_count,
        report.urgent_count,
        report.cve_count,
        report.news_count,
    )
    urgent_messages = render_digest_messages(urgent)

    store = Store(cfg.database_path)
    try:
        if dry_run:
            console.print(f"[bold]Generated report:[/bold] {report.archive_path}")
            console.print()
            console.print("[bold]Telegram summary[/bold]")
            console.print(summary_message)
            if urgent:
                console.print()
                for index, message in enumerate(urgent_messages, start=1):
                    if len(urgent_messages) > 1:
                        console.print(f"[bold]Urgent Telegram message {index}/{len(urgent_messages)}[/bold]")
                    console.print(message.text)
                    if index < len(urgent_messages):
                        console.print()
            return

        publish_report(report, cfg.github_pages)
        store.upsert_items(items)
        summary_sent = False
        if store.should_send_report_summary(report.date.isoformat(), content_hash):
            send_message(summary_message)
            store.mark_report_summary_sent(report.date.isoformat(), content_hash)
            summary_sent = True

        unsent_urgent = store.filter_unsent(urgent)
        if not unsent_urgent:
            if summary_sent:
                console.print("Sent report summary; no new urgent RCE exploited items.")
            else:
                console.print("No new report summary or urgent items to send.")
            return

        sent_count = 0
        urgent_messages = render_digest_messages(unsent_urgent)
        for message in urgent_messages:
            send_message(message.text)
            store.mark_sent(message.items)
            sent_count += len(message.items)
        console.print(
            f"Sent report summary: {summary_sent}. Sent {len(urgent_messages)} urgent message(s) with {sent_count} item(s)."
        )
    finally:
        store.close()


@app.command("publish-report")
def publish_report_only(
    config: Path = typer.Option(DEFAULT_CONFIG_PATH, "--config", "-c", help="Path to config.yaml."),
) -> None:
    cfg = load_config(config)
    items = annotate_items(_collect_items(cfg), cfg.risk)
    urgent = filter_urgent_items(items, cfg.risk)
    report = generate_html_report(items, urgent, cfg.github_pages)
    publish_report(report, cfg.github_pages)
    console.print(f"Published report: {report.archive_url}")


@app.command("preview-report")
def preview_report(
    config: Path = typer.Option(DEFAULT_CONFIG_PATH, "--config", "-c", help="Path to config.yaml."),
) -> None:
    cfg = load_config(config)
    items = annotate_items(_collect_items(cfg), cfg.risk)
    urgent = filter_urgent_items(items, cfg.risk)
    report = generate_html_report(items, urgent, cfg.github_pages)
    console.print(f"Generated report: {report.archive_path}")
    console.print(f"Latest report: {report.latest_path}")


@app.command("list-unsent")
def list_unsent(
    config: Path = typer.Option(DEFAULT_CONFIG_PATH, "--config", "-c", help="Path to config.yaml."),
) -> None:
    cfg = load_config(config)
    items = filter_urgent_items(annotate_items(_collect_items(cfg), cfg.risk), cfg.risk)
    store = Store(cfg.database_path)
    try:
        store.upsert_items(items)
        unsent = store.filter_unsent(items)
    finally:
        store.close()

    table = Table("Kind", "Source", "Title", "Reasons")
    for item in unsent:
        table.add_row(item.kind.value, item.source, item.title, ", ".join(item.reasons))
    console.print(table)


@app.command("test-telegram")
def test_telegram() -> None:
    send_message("Bot Security News test message.")
    console.print("Telegram test message sent.")


def _collect_items(cfg) -> list[SecurityItem]:
    items: list[SecurityItem] = []
    items.extend(_safe_collect("NVD", lambda: fetch_recent_cves(cfg.lookback_hours, cfg.http_timeout_seconds)))
    items.extend(_safe_collect("CISA KEV", lambda: fetch_cisa_kev(cfg.lookback_hours, cfg.http_timeout_seconds)))
    items.extend(_safe_collect("RSS", lambda: fetch_rss_items(cfg.rss_feeds, cfg.lookback_hours)))
    _safe_collect("EPSS", lambda: enrich_with_epss(items, cfg.http_timeout_seconds))
    return _dedupe(items)


def _safe_collect(name: str, fn):
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001 - source isolation is intentional for a daily digest.
        console.print(f"[yellow]{name} collection failed:[/yellow] {exc}")
        return []


def _dedupe(items: list[SecurityItem]) -> list[SecurityItem]:
    deduped: dict[str, SecurityItem] = {}
    for item in items:
        existing = deduped.get(item.stable_id)
        if existing is None:
            deduped[item.stable_id] = item
            continue
        existing.is_kev = existing.is_kev or item.is_kev
        existing.reasons.extend(reason for reason in item.reasons if reason not in existing.reasons)
        if not existing.summary and item.summary:
            existing.summary = item.summary
    return list(deduped.values())


def _content_hash(items: list[SecurityItem]) -> str:
    digest = hashlib.sha256()
    for item in sorted(items, key=lambda value: value.stable_id):
        digest.update(item.stable_id.encode("utf-8"))
        digest.update(item.published_iso.encode("utf-8"))
        digest.update(",".join(item.reasons).encode("utf-8"))
    return digest.hexdigest()

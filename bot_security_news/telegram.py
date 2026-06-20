from __future__ import annotations

from dataclasses import dataclass
import os

import httpx
from dotenv import load_dotenv

from .models import ItemKind, SecurityItem


TELEGRAM_LIMIT = 4096
DEFAULT_ITEMS_PER_MESSAGE = 3
ITEM_SEPARATOR = "-----------------"


class TelegramConfigError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class DigestMessage:
    text: str
    items: list[SecurityItem]


def render_digest(items: list[SecurityItem]) -> str:
    return "\n\n".join(message.text for message in render_digest_messages(items))


def render_report_summary(
    report_url: str,
    total_count: int,
    urgent_count: int,
    cve_count: int,
    news_count: int,
) -> str:
    return "\n".join(
        [
            "Daily Cybersecurity Report",
            f"Total collected: {total_count}",
            f"Urgent RCE exploited: {urgent_count}",
            f"CVEs: {cve_count}",
            f"News: {news_count}",
            f"Read full report: {report_url}",
        ]
    )


def render_digest_messages(
    items: list[SecurityItem],
    items_per_message: int = DEFAULT_ITEMS_PER_MESSAGE,
) -> list[DigestMessage]:
    if not items:
        return [DigestMessage("Security digest: no high-risk items found in this run.", [])]

    visible = items
    chunks = [visible[index : index + items_per_message] for index in range(0, len(visible), items_per_message)]
    messages: list[DigestMessage] = []
    for index, chunk in enumerate(chunks, start=1):
        messages.append(DigestMessage(_render_chunk(chunk, index, len(chunks)), chunk))
    return messages


def send_message(message: str, token: str | None = None, chat_id: str | None = None) -> None:
    load_dotenv()
    token = token or os.getenv("TELEGRAM_BOT_TOKEN")
    chat_id = chat_id or os.getenv("TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        raise TelegramConfigError("TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID are required")

    response = httpx.post(
        f"https://api.telegram.org/bot{token}/sendMessage",
        json={
            "chat_id": chat_id,
            "text": message,
            "disable_web_page_preview": True,
        },
        timeout=30,
    )
    response.raise_for_status()


def _format_item(item: SecurityItem) -> list[str]:
    title = item.title.strip()
    reason = ", ".join(item.reasons) if item.reasons else "high signal"
    cve = f"{item.cve_id} - " if item.cve_id and item.cve_id not in title else ""
    summary = _compact(item.summary, 180)
    lines = [f"- [{_item_label(item)}] {cve}{title}", f"  Reason: {reason}", f"  Link: {item.url}"]
    if summary:
        lines.insert(2, f"  Note: {summary}")
    return lines


def _render_chunk(chunk: list[SecurityItem], part: int, total_parts: int) -> str:
    title = "Daily Cybersecurity Digest"
    if total_parts > 1:
        title = f"{title} ({part}/{total_parts})"

    lines = [title, ""]
    for index, item in enumerate(chunk):
        if index > 0:
            lines.append(ITEM_SEPARATOR)
        lines.extend(_format_item(item))

    message = "\n".join(lines).strip()
    if len(message) <= TELEGRAM_LIMIT:
        return message
    return message[: TELEGRAM_LIMIT - 80].rstrip() + "\n\n[Digest truncated to fit Telegram limit.]"


def _item_label(item: SecurityItem) -> str:
    if item.is_kev or item.kind == ItemKind.KEV:
        return "Known Exploited"
    if item.kind == ItemKind.CVE:
        return "Critical/High CVE"
    return "Breach & Hack News"


def _compact(text: str, limit: int) -> str:
    clean = " ".join((text or "").split())
    if len(clean) <= limit:
        return clean
    return clean[: limit - 3].rstrip() + "..."

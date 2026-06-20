from __future__ import annotations

import time
from typing import Any

import httpx


RETRY_STATUS_CODES = {429, 500, 502, 503, 504}


def get_json(
    url: str,
    *,
    params: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 30,
    retries: int = 2,
) -> dict[str, Any]:
    request_headers = {"User-Agent": "bot-security-news/0.1"}
    if headers:
        request_headers.update(headers)

    last_error: Exception | None = None
    for attempt in range(retries + 1):
        try:
            response = httpx.get(url, params=params, headers=request_headers, timeout=timeout)
            if response.status_code in RETRY_STATUS_CODES and attempt < retries:
                time.sleep(2**attempt)
                continue
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as exc:
            last_error = exc
            if attempt < retries:
                time.sleep(2**attempt)
                continue
            raise
    raise RuntimeError(f"Request failed for {url}") from last_error

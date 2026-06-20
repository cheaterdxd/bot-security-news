from __future__ import annotations

import subprocess
from pathlib import Path

from .models import GitHubPagesConfig
from .report import ReportResult


class PublishError(RuntimeError):
    pass


def publish_report(report: ReportResult, github_pages: GitHubPagesConfig) -> None:
    if not github_pages.remote_url:
        raise PublishError("github_pages.remote_url is required to publish the HTML report")
    if not github_pages.base_url:
        raise PublishError("github_pages.base_url is required before sending a GitHub Pages link")

    docs_dir = Path(github_pages.docs_dir)
    _ensure_git_repo(github_pages)
    _git(["add", str(docs_dir)])
    diff = _git(["diff", "--cached", "--quiet"], check=False)
    if diff.returncode == 0:
        return
    _git(["commit", "-m", f"Update security report {report.date.isoformat()}"])
    _git(["push", "-u", "origin", github_pages.branch])


def _ensure_git_repo(github_pages: GitHubPagesConfig) -> None:
    status = _git(["rev-parse", "--is-inside-work-tree"], check=False)
    if status.returncode != 0:
        _git(["init", "-b", github_pages.branch])

    remote = _git(["remote", "get-url", "origin"], check=False)
    if remote.returncode != 0:
        _git(["remote", "add", "origin", github_pages.remote_url])
    elif remote.stdout.strip() != github_pages.remote_url:
        _git(["remote", "set-url", "origin", github_pages.remote_url])


def _git(args: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        ["git", *args],
        check=False,
        capture_output=True,
        text=True,
    )
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise PublishError(f"git {' '.join(args)} failed: {detail}")
    return result

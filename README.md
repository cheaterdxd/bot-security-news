# Bot Security News

Daily Python digest for cybersecurity updates. It sends only strict urgent RCE/exploited items to Telegram, and publishes the rest into a simple GitHub Pages HTML report.

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
Copy-Item .env.example .env
```

Edit `.env`:

```text
TELEGRAM_BOT_TOKEN=123456:telegram-token
TELEGRAM_CHAT_ID=123456789
NVD_API_KEY=
```

Edit `config.yaml` for thresholds, RSS feeds, and GitHub Pages:

```yaml
github_pages:
  remote_url: https://github.com/YOUR_USER/YOUR_REPO.git
  base_url: https://YOUR_USER.github.io/YOUR_REPO
  branch: main
  docs_dir: docs
```

Create the GitHub repo first, then enable Pages from `/docs` on the `main` branch.

## Commands

```powershell
bot-security-news test-telegram
bot-security-news collect --dry-run
bot-security-news collect
bot-security-news list-unsent
bot-security-news preview-report
bot-security-news publish-report
```

The default SQLite database is `data/security_news.sqlite3`.

## Scheduling

Windows Task Scheduler example:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "cd D:\Code\botSecurityNews; .\.venv\Scripts\bot-security-news.exe collect"
```

Linux cron example:

```cron
15 8 * * * cd /opt/botSecurityNews && ./.venv/bin/bot-security-news collect >> logs/cron.log 2>&1
```

## Signal Rules

Telegram urgent details are sent only when all of these are true:

- CVSS score is greater than `9.0`.
- The item mentions RCE or code execution.
- The item has exploitation evidence, either CISA KEV or active exploitation wording.

The HTML report includes all collected items. The page intentionally stays simple: one scrollable list of bordered news blocks.

An item gets signal labels when any of these is true:

- It is in CISA Known Exploited Vulnerabilities.
- CVSS score is at least `8.0`.
- EPSS probability is at least `0.5`.
- RSS title/summary contains configured incident keywords such as `breach`, `ransomware`, `zero-day`, or `exploited`.
